//! Golden tests for the two ForgeSpec lowering paths (R438-T7).
//!
//! Two consumers of [`task::ForgeSpec`] live in the cloud reconciler:
//!
//! - W164 transform recipes — [`super::static_asset::lower_recipe_step_to_forge_spec`]
//! - W165 mesofact-static builds — [`super::mesofact_static::lower_build_to_forge_spec`]
//!
//! These are independent helpers because the inputs differ (a recipe carries
//! an image + per-step argv + per-step timeout; a build carries a shell-string
//! command + a build_mode). The **shape** of the lowered ForgeSpec is the
//! parity property: both consumers must land in the same
//! `Subprocess + Local + Container` quadrant with a pinned image, so the
//! downstream `ForgeExecutor` dispatch is identical for both.
//!
//! These tests pin the lowering output explicitly so a drift in either path
//! shows up as a single-file regression with a clear diff.

use std::path::PathBuf;

use velveteen_exec::transforms::{RecipeLocation, RecipePlacement, RecipeStep, TransformRecipe};
use velveteen::{ForgeCommand, ForgeSpec, Initiator, MeshAccess, TaskLocation, TaskRuntime};
use workload_spec::{BuildConfig, BuildMode, ImageRef};

use super::mesofact_static::lower_build_to_forge_spec;
use super::static_asset::lower_recipe_step_to_forge_spec;

// ── Fixtures ─────────────────────────────────────────────────────────────────

const GOLDEN_DIGEST: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";

fn golden_image() -> ImageRef {
    ImageRef {
        registry: "ghcr.io".into(),
        repository: "yah/transform-tool".into(),
        tag: "v1.0.0".into(),
        digest: GOLDEN_DIGEST.into(),
    }
}

fn golden_recipe() -> TransformRecipe {
    TransformRecipe {
        name: "whisper-quantize".into(),
        label: "Whisper Q5_K quantize".into(),
        placement: RecipePlacement {
            location: RecipeLocation::Local,
            runtime: TaskRuntime::Container,
            platform: None,
        },
        image: golden_image(),
        steps: vec![RecipeStep {
            name: "quantize".into(),
            argv: vec![
                "./quantize".into(),
                "{{YAH_TRANSFORM_IN_0}}".into(),
                "{{YAH_TRANSFORM_OUT}}".into(),
                "q5_k".into(),
            ],
            timeout: 600,
        }],
    }
}

fn golden_build_in_container() -> (BuildConfig, BuildMode) {
    (
        BuildConfig {
            command: "bun run build".into(),
            out_dir: PathBuf::from("dist"),
            render_command: None,
        },
        BuildMode::InContainer {
            image: golden_image(),
        },
    )
}

fn golden_build_host_side() -> (BuildConfig, BuildMode) {
    (
        BuildConfig {
            command: "bun run build".into(),
            out_dir: PathBuf::from("dist"),
            render_command: None,
        },
        BuildMode::HostSide,
    )
}

/// Assert that a [`ForgeSpec`] sits in the canonical "local container
/// subprocess with a pinned image" quadrant. Both lowering consumers must
/// share this shape; differences in argv/timeout/label/initiator are
/// expected and don't violate parity.
fn assert_subprocess_local_container_pinned(spec: &ForgeSpec) {
    assert_eq!(
        spec.where_.location,
        TaskLocation::Local,
        "lowering must target the local quadrant"
    );
    assert_eq!(
        spec.where_.runtime,
        TaskRuntime::Container,
        "lowering must target the container runtime"
    );
    assert_eq!(
        spec.mesh_access,
        MeshAccess::None,
        "neither consumer requests mesh access"
    );
    match &spec.command {
        ForgeCommand::Subprocess { image, .. } => {
            let image = image
                .as_ref()
                .expect("container quadrant requires an image");
            assert!(
                image.digest.starts_with("sha256:"),
                "image digest must be content-addressed; got {:?}",
                image.digest
            );
            assert!(
                !image.digest.trim_start_matches("sha256:").is_empty(),
                "digest body must be non-empty"
            );
        }
        other => panic!("expected ForgeCommand::Subprocess, got {other:?}"),
    }
}

// ── Recipe → ForgeSpec golden ─────────────────────────────────────────────────

#[test]
fn golden_recipe_step_lowers_to_pinned_local_container_subprocess() {
    let recipe = golden_recipe();
    let step = &recipe.steps[0];
    // Substituted argv: caller binds YAH_TRANSFORM_IN_0 / _OUT before
    // handing argv to the lowering. The golden expectation pins the
    // post-substitution shape.
    let argv = vec![
        "./quantize".into(),
        "/tmp/cache/in.bin".into(),
        "/tmp/out/whisper.q5_k.bin".into(),
        "q5_k".into(),
    ];

    let spec = lower_recipe_step_to_forge_spec(&recipe, step, argv.clone());

    // Quadrant
    assert_subprocess_local_container_pinned(&spec);

    // Command
    match spec.command {
        ForgeCommand::Subprocess {
            argv: spec_argv,
            image,
        } => {
            assert_eq!(spec_argv, argv);
            let image = image.unwrap();
            assert_eq!(image.registry, "ghcr.io");
            assert_eq!(image.repository, "yah/transform-tool");
            assert_eq!(image.tag, "v1.0.0");
            assert_eq!(image.digest, GOLDEN_DIGEST);
        }
        other => panic!("expected Subprocess, got {other:?}"),
    }

    // Timeout: recipe step's 600s lifts to Some(Millis::from_secs(600)).
    let timeout = spec.timeout.expect("non-zero step.timeout maps to Some");
    assert_eq!(timeout.as_ms(), 600 * 1000);

    // Label + initiator are reconciler-attributed.
    assert_eq!(
        spec.label.as_deref(),
        Some("transform:whisper-quantize:quantize")
    );
    match spec.initiator {
        Initiator::Gnome { camp, shift } => {
            assert_eq!(camp, "static-asset-reconciler");
            assert_eq!(shift, "derive-whisper-quantize");
        }
        other => panic!("expected Gnome initiator, got {other:?}"),
    }
}

#[test]
fn golden_recipe_step_with_zero_timeout_lowers_to_none() {
    let mut recipe = golden_recipe();
    recipe.steps[0].timeout = 0;
    let step = &recipe.steps[0];
    let spec = lower_recipe_step_to_forge_spec(&recipe, step, vec!["./quantize".into()]);
    assert!(
        spec.timeout.is_none(),
        "step.timeout=0 must lower to None (no wall-clock cap)"
    );
}

// ── BuildMode → ForgeSpec golden ──────────────────────────────────────────────

#[test]
fn golden_build_in_container_lowers_to_pinned_local_container_subprocess() {
    let workload_dir = PathBuf::from("/workspace/app/web");
    let (build, mode) = golden_build_in_container();

    let spec = lower_build_to_forge_spec(&workload_dir, &build, &mode);

    // Quadrant — same as the recipe lowering.
    assert_subprocess_local_container_pinned(&spec);

    // Command: sh -c shell wrapping the build.command string.
    match spec.command {
        ForgeCommand::Subprocess { argv, image } => {
            assert_eq!(
                argv,
                vec!["sh".to_string(), "-c".into(), "bun run build".into()]
            );
            let image = image.unwrap();
            assert_eq!(image.registry, "ghcr.io");
            assert_eq!(image.repository, "yah/transform-tool");
            assert_eq!(image.digest, GOLDEN_DIGEST);
        }
        other => panic!("expected Subprocess, got {other:?}"),
    }

    // Timeout: build path leaves it unbounded (operators set their own).
    assert!(spec.timeout.is_none(), "build lowering carries no timeout");

    // Label embeds the workload_dir for operator-side identification.
    assert_eq!(
        spec.label.as_deref(),
        Some("mesofact-static-build:/workspace/app/web")
    );
    match spec.initiator {
        Initiator::Gnome { camp, shift } => {
            assert_eq!(camp, "mesofact-static-reconciler");
            assert_eq!(shift, "build");
        }
        other => panic!("expected Gnome initiator, got {other:?}"),
    }
}

#[test]
fn golden_build_host_side_lowers_to_native_quadrant_without_image() {
    let workload_dir = PathBuf::from("/workspace/app/web");
    let (build, mode) = golden_build_host_side();

    let spec = lower_build_to_forge_spec(&workload_dir, &build, &mode);

    assert_eq!(spec.where_.location, TaskLocation::Local);
    assert_eq!(
        spec.where_.runtime,
        TaskRuntime::Native,
        "host_side must target the native runtime"
    );
    match spec.command {
        ForgeCommand::Subprocess { image, .. } => {
            assert!(
                image.is_none(),
                "host_side must carry no image (Native runtime); got {image:?}"
            );
        }
        other => panic!("expected Subprocess, got {other:?}"),
    }
}

// ── Parity: both lowerings produce the same quadrant ─────────────────────────

/// The canonical R438 parity property: a recipe step and a build_mode that
/// both target containerised local execution lower to the SAME
/// `(TaskLocation::Local, TaskRuntime::Container, ForgeCommand::Subprocess
/// with pinned image)` quadrant. This is the architectural invariant that
/// lets a single `ForgeExecutor` dispatch (T13) handle both consumers
/// uniformly — drift in either lowering breaks the shared executor path.
#[test]
fn parity_recipe_and_build_in_container_share_quadrant() {
    let recipe = golden_recipe();
    let recipe_spec = lower_recipe_step_to_forge_spec(
        &recipe,
        &recipe.steps[0],
        vec!["./quantize".into(), "in".into(), "out".into()],
    );

    let workload_dir = PathBuf::from("/workspace/app/web");
    let (build, mode) = golden_build_in_container();
    let build_spec = lower_build_to_forge_spec(&workload_dir, &build, &mode);

    // Both share the quadrant shape.
    assert_subprocess_local_container_pinned(&recipe_spec);
    assert_subprocess_local_container_pinned(&build_spec);
    assert_eq!(recipe_spec.where_, build_spec.where_);

    // Both carry the same kind of image (digest-pinned, sha256 algorithm).
    let recipe_image = match &recipe_spec.command {
        ForgeCommand::Subprocess { image, .. } => image.as_ref().unwrap(),
        _ => unreachable!(),
    };
    let build_image = match &build_spec.command {
        ForgeCommand::Subprocess { image, .. } => image.as_ref().unwrap(),
        _ => unreachable!(),
    };
    assert!(
        recipe_image.digest.starts_with("sha256:") && build_image.digest.starts_with("sha256:"),
        "both lowerings must emit sha256-pinned images"
    );

    // Initiator vocabulary differs by camp string but uses the same Gnome
    // variant — this keeps audit traces attributable to the reconciler.
    assert!(matches!(recipe_spec.initiator, Initiator::Gnome { .. }));
    assert!(matches!(build_spec.initiator, Initiator::Gnome { .. }));
}
