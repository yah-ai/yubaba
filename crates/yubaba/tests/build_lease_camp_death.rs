//! R1019-F4 verify: a camp process that dies mid-lease. Its renewals stop,
//! the machine expires the lease within the TTL, stops the leased workload,
//! and the freed slot is granted to a second camp (W384 §2.4 rule 1/2).
//!
//! Driven against the machine's own `GrantTable` with an injected clock, so
//! "the camp dies" is simply "no more `renew` calls from it".

use std::time::{Duration, Instant};

use yubaba::build_grants::{
    AcquireRequest, Capacity, GrantState, GrantTable, Holder, Needs, Refusal, DEFAULT_TTL,
};

fn one_slot() -> Capacity {
    Capacity {
        memory_mb: 8_000,
        cpu_millis: 8_000,
        disk_mb: 50_000,
        max_grants: 1,
        arch: "x86_64".into(),
        deadline_enforced: true,
    }
}

fn ask(camp: &str) -> AcquireRequest {
    AcquireRequest {
        holder: Holder { camp: camp.into(), session: Some(format!("session:{camp}")), ticket: None },
        needs: Needs { memory_mb: 4_096, cpu_millis: 4_000, ..Default::default() },
        ..Default::default()
    }
}

#[test]
fn a_dead_camps_lease_expires_within_the_ttl_and_its_slot_goes_to_a_second_camp() {
    let mut table = GrantTable::new(one_slot(), 1);
    let t0 = Instant::now();
    let s = |secs: u64| t0 + Duration::from_secs(secs);

    // Camp A holds the only slot and runs a build under it.
    let a = table.acquire(ask("camp-a"), t0).expect("an empty machine grants");
    assert_eq!(a.ttl_ms, DEFAULT_TTL.as_millis() as u64);
    table.bind_deploy(&a.id, "forge.a", s(1)).expect("the leased deploy binds");

    // Alive: camp A renews every 30 s (the camp's RENEW_EVERY), and holds the slot.
    table.renew(&a.id, a.epoch, s(30)).unwrap();
    table.renew(&a.id, a.epoch, s(60)).unwrap();
    assert!(matches!(table.acquire(ask("camp-b"), s(61)), Err(Refusal::AtGrantLimit { limit: 1 })));

    // Camp A's process dies after the renewal at 60 s: no more renewals.
    // Inside the TTL nothing is reclaimed.
    assert!(table.expire(s(60) + DEFAULT_TTL - Duration::from_secs(1)).is_empty());
    assert!(matches!(table.acquire(ask("camp-b"), s(149)), Err(Refusal::AtGrantLimit { .. })));

    // One TTL after the last renewal the machine expires it and hands back the
    // workload to stop through kamaji.
    let stop = table.expire(s(60) + DEFAULT_TTL);
    assert_eq!(stop, vec![(a.id.clone(), "forge.a".to_string())]);
    assert!(matches!(table.get(&a.id).unwrap().state, GrantState::Expired { .. }));

    // The slot is free for a second camp, under a newer epoch, and camp A's
    // stale lease can no longer be renewed back to life.
    let b = table.acquire(ask("camp-b"), s(151)).expect("the expired slot is grantable");
    assert!(b.epoch > a.epoch, "epochs fence the old holder: {} vs {}", b.epoch, a.epoch);
    assert_eq!(b.holder.camp, "camp-b");
    assert!(table.renew(&a.id, a.epoch, s(152)).is_err());
}
