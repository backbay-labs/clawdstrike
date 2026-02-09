use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

#[cfg(browser)]
wasm_bindgen_test_configure!(run_in_browser);

#[cfg(feature = "serde")]
#[wasm_bindgen_test]
pub fn test_serde() {
    use wasmtimer::std::SystemTime;
    let now = SystemTime::now();
    let serialized = serde_json::to_string(&now).unwrap();
    let deserialized: SystemTime = serde_json::from_str(&serialized).unwrap();
    assert_eq!(now, deserialized);
}

#[cfg(feature = "tokio-test-util")]
pub mod tokio_tests {
    use super::*;
    use std::{pin::Pin, sync::Once, time::Duration};

    use futures::{task::noop_waker_ref, Future};
    use std::task::{Context, Poll};
    use wasmtimer::std::Instant;
    use wasmtimer::tokio::{advance, pause};

    static INIT: Once = Once::new();

    pub fn initialize() {
        INIT.call_once(|| {
            pause();
        });
    }

    #[wasm_bindgen_test]
    pub async fn test_micro_second_precision() {
        initialize();
        let a = Instant::now();
        advance(Duration::from_micros(435)).await;
        let b = Instant::now();
        let diff = b - a;
        assert_eq!(diff.as_micros(), 435);
    }

    pub mod sleep_tests {

        use super::*;
        use wasmtimer::tokio::sleep;

        #[wasm_bindgen_test]
        async fn is_elapsed_test() {
            initialize();
            let slept = sleep(Duration::from_millis(1000));
            assert!(!slept.is_elapsed());
            advance(Duration::from_millis(1005)).await;
            assert!(slept.is_elapsed());
        }

        #[wasm_bindgen_test]
        async fn poll_test() {
            initialize();
            let waker = noop_waker_ref();
            let mut cx = Context::from_waker(waker);

            let mut slept = sleep(Duration::from_millis(1000));
            assert_eq!(Pin::new(&mut slept).poll(&mut cx), Poll::Pending);
            advance(Duration::from_millis(1005)).await;
            assert_eq!(Pin::new(&mut slept).poll(&mut cx), Poll::Ready(()));
        }

        #[wasm_bindgen_test]
        async fn reset_before_exec_test() {
            initialize();
            let waker = noop_waker_ref();
            let mut cx = Context::from_waker(waker);

            let mut slept = sleep(Duration::from_millis(1000));
            Pin::new(&mut slept).reset(Instant::now() + Duration::from_millis(2000));
            assert_eq!(Pin::new(&mut slept).poll(&mut cx), Poll::Pending);
            advance(Duration::from_millis(1005)).await;
            assert_eq!(Pin::new(&mut slept).poll(&mut cx), Poll::Pending);
            advance(Duration::from_millis(1005)).await;
            assert_eq!(Pin::new(&mut slept).poll(&mut cx), Poll::Ready(()));
        }

        #[wasm_bindgen_test]
        async fn reset_after_exec_test() {
            initialize();
            let waker = noop_waker_ref();
            let mut cx = Context::from_waker(waker);

            let mut slept = sleep(Duration::from_millis(1000));
            assert_eq!(Pin::new(&mut slept).poll(&mut cx), Poll::Pending);
            advance(Duration::from_millis(1005)).await;
            assert_eq!(Pin::new(&mut slept).poll(&mut cx), Poll::Ready(()));
            Pin::new(&mut slept).reset(Instant::now() + Duration::from_millis(1500));
            assert_eq!(Pin::new(&mut slept).poll(&mut cx), Poll::Pending);
            advance(Duration::from_millis(1505)).await;
            assert_eq!(Pin::new(&mut slept).poll(&mut cx), Poll::Ready(()));
        }
    }

    pub mod interval_tests {

        use wasmtimer::tokio::{interval, interval_at, MissedTickBehavior};

        use super::*;

        #[wasm_bindgen_test]
        async fn interval_tick_test() {
            initialize();

            let waker = noop_waker_ref();
            let mut cx = Context::from_waker(waker);

            let mut interval = interval(Duration::from_millis(500));
            let mut fut = interval.tick();
            unsafe {
                assert_ne!(Pin::new_unchecked(&mut fut).poll(&mut cx), Poll::Pending);
            }
            drop(fut);
            let mut fut2 = interval.tick();
            unsafe {
                assert_eq!(Pin::new_unchecked(&mut fut2).poll(&mut cx), Poll::Pending);
            }
            advance(Duration::from_millis(501)).await;
            unsafe {
                assert!(matches!(
                    Pin::new_unchecked(&mut fut2).poll(&mut cx),
                    Poll::Ready(_)
                ));
            }
            drop(fut2);
            let mut fut3 = interval.tick();
            unsafe {
                assert_eq!(Pin::new_unchecked(&mut fut3).poll(&mut cx), Poll::Pending);
            }
            advance(Duration::from_millis(501)).await;
            unsafe {
                assert!(matches!(
                    Pin::new_unchecked(&mut fut3).poll(&mut cx),
                    Poll::Ready(_)
                ));
            }
        }

        #[wasm_bindgen_test]
        async fn interval_at_tick_test() {
            initialize();

            let waker = noop_waker_ref();
            let mut cx = Context::from_waker(waker);

            let mut interval = interval_at(
                Instant::now() + Duration::from_millis(1000),
                Duration::from_millis(500),
            );
            let mut fut = interval.tick();
            unsafe {
                assert_eq!(Pin::new_unchecked(&mut fut).poll(&mut cx), Poll::Pending);
            }
            advance(Duration::from_millis(501)).await;
            unsafe {
                assert_eq!(Pin::new_unchecked(&mut fut).poll(&mut cx), Poll::Pending);
            }
            advance(Duration::from_millis(501)).await;
            unsafe {
                assert!(matches!(
                    Pin::new_unchecked(&mut fut).poll(&mut cx),
                    Poll::Ready(_)
                ));
            }
            drop(fut);
            let mut fut2 = interval.tick();
            unsafe {
                assert_eq!(Pin::new_unchecked(&mut fut2).poll(&mut cx), Poll::Pending);
            }
            advance(Duration::from_millis(501)).await;
            unsafe {
                assert!(matches!(
                    Pin::new_unchecked(&mut fut2).poll(&mut cx),
                    Poll::Ready(_)
                ));
            }
        }

        #[wasm_bindgen_test]
        async fn interval_poll_tick_test() {
            initialize();

            let waker = noop_waker_ref();
            let mut cx = Context::from_waker(waker);

            let mut interval = interval(Duration::from_millis(500));
            assert_ne!(interval.poll_tick(&mut cx), Poll::Pending);
            assert_eq!(interval.poll_tick(&mut cx), Poll::Pending);
            advance(Duration::from_millis(501)).await;
            assert!(matches!(interval.poll_tick(&mut cx), Poll::Ready(_)));
            assert_eq!(interval.poll_tick(&mut cx), Poll::Pending);
            advance(Duration::from_millis(501)).await;
            assert!(matches!(interval.poll_tick(&mut cx), Poll::Ready(_)));
        }

        #[wasm_bindgen_test]
        async fn interval_at_poll_tick_test() {
            initialize();

            let waker = noop_waker_ref();
            let mut cx = Context::from_waker(waker);

            let mut interval = interval_at(
                Instant::now() + Duration::from_millis(1000),
                Duration::from_millis(500),
            );
            assert_eq!(interval.poll_tick(&mut cx), Poll::Pending);
            advance(Duration::from_millis(501)).await;
            assert_eq!(interval.poll_tick(&mut cx), Poll::Pending);
            advance(Duration::from_millis(501)).await;
            assert!(matches!(interval.poll_tick(&mut cx), Poll::Ready(_)));
            assert_eq!(interval.poll_tick(&mut cx), Poll::Pending);
            advance(Duration::from_millis(501)).await;
            assert!(matches!(interval.poll_tick(&mut cx), Poll::Ready(_)));
        }

        #[wasm_bindgen_test]
        async fn reset_test() {
            initialize();

            let waker = noop_waker_ref();
            let mut cx = Context::from_waker(waker);

            let mut interval = interval(Duration::from_millis(500));
            assert_ne!(interval.poll_tick(&mut cx), Poll::Pending);
            assert_eq!(interval.poll_tick(&mut cx), Poll::Pending);
            advance(Duration::from_millis(301)).await;
            assert_eq!(interval.poll_tick(&mut cx), Poll::Pending);
            interval.reset();
            advance(Duration::from_millis(201)).await;
            assert_eq!(interval.poll_tick(&mut cx), Poll::Pending);
            advance(Duration::from_millis(301)).await;
            assert!(matches!(interval.poll_tick(&mut cx), Poll::Ready(_)));
        }

        #[wasm_bindgen_test]
        async fn interval_at_reset_test() {
            initialize();

            let waker = noop_waker_ref();
            let mut cx = Context::from_waker(waker);

            let mut interval = interval_at(
                Instant::now() + Duration::from_millis(1000),
                Duration::from_millis(500),
            );
            assert_eq!(interval.poll_tick(&mut cx), Poll::Pending);
            advance(Duration::from_millis(301)).await;
            assert_eq!(interval.poll_tick(&mut cx), Poll::Pending);
            interval.reset();
            advance(Duration::from_millis(201)).await;
            assert_eq!(interval.poll_tick(&mut cx), Poll::Pending);
            advance(Duration::from_millis(301)).await;
            assert!(matches!(interval.poll_tick(&mut cx), Poll::Ready(_)));
        }

        #[wasm_bindgen_test]
        async fn missed_tick_behavior_burst_test() {
            initialize();

            let waker = noop_waker_ref();
            let mut cx = Context::from_waker(waker);

            let mut interval = interval(Duration::from_millis(500));
            interval.set_missed_tick_behavior(MissedTickBehavior::Burst);
            advance(Duration::from_millis(1501)).await;
            assert!(matches!(interval.poll_tick(&mut cx), Poll::Ready(_)));
            assert!(matches!(interval.poll_tick(&mut cx), Poll::Ready(_)));
            assert!(matches!(interval.poll_tick(&mut cx), Poll::Ready(_)));
            assert!(matches!(interval.poll_tick(&mut cx), Poll::Ready(_)));
            assert_eq!(interval.poll_tick(&mut cx), Poll::Pending);
        }

        #[wasm_bindgen_test]
        async fn missed_tick_behavior_skip_test() {
            initialize();

            let waker = noop_waker_ref();
            let mut cx = Context::from_waker(waker);

            let mut interval = interval(Duration::from_millis(500));
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            advance(Duration::from_millis(1601)).await;
            assert!(matches!(interval.poll_tick(&mut cx), Poll::Ready(_)));
            assert_eq!(interval.poll_tick(&mut cx), Poll::Pending);
            advance(Duration::from_millis(401)).await;
            assert!(matches!(interval.poll_tick(&mut cx), Poll::Ready(_)));
            assert_eq!(interval.poll_tick(&mut cx), Poll::Pending);
        }

        #[wasm_bindgen_test]
        async fn missed_tick_behavior_delay_test() {
            initialize();

            let waker = noop_waker_ref();
            let mut cx = Context::from_waker(waker);

            let mut interval = interval(Duration::from_millis(500));
            interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
            advance(Duration::from_millis(1601)).await;
            assert!(matches!(interval.poll_tick(&mut cx), Poll::Ready(_)));
            assert_eq!(interval.poll_tick(&mut cx), Poll::Pending);
            advance(Duration::from_millis(401)).await;
            assert_eq!(interval.poll_tick(&mut cx), Poll::Pending);
            advance(Duration::from_millis(100)).await;
            assert!(matches!(interval.poll_tick(&mut cx), Poll::Ready(_)));
            assert_eq!(interval.poll_tick(&mut cx), Poll::Pending);
        }
    }

    pub mod timeout_tests {

        use super::*;
        use wasmtimer::tokio::{sleep, timeout, timeout_at};

        #[wasm_bindgen_test]
        async fn timeout_success_test() {
            initialize();

            let waker = noop_waker_ref();
            let mut cx = Context::from_waker(waker);

            let mut fut = timeout(
                Duration::from_millis(1500),
                sleep(Duration::from_millis(1000)),
            );
            assert_eq!(Pin::new(&mut fut).poll(&mut cx), Poll::Pending);
            advance(Duration::from_millis(1001)).await;
            assert!(matches!(
                Pin::new(&mut fut).poll(&mut cx),
                Poll::Ready(Ok(_))
            ));
        }

        #[wasm_bindgen_test]
        async fn timeout_fail_test() {
            initialize();

            let waker = noop_waker_ref();
            let mut cx = Context::from_waker(waker);

            let mut fut = timeout(
                Duration::from_millis(1000),
                sleep(Duration::from_millis(1500)),
            );
            assert_eq!(Pin::new(&mut fut).poll(&mut cx), Poll::Pending);
            advance(Duration::from_millis(1001)).await;
            assert!(matches!(
                Pin::new(&mut fut).poll(&mut cx),
                Poll::Ready(Err(_))
            ));
        }

        #[wasm_bindgen_test]
        async fn timeout_at_success_test() {
            initialize();

            let waker = noop_waker_ref();
            let mut cx = Context::from_waker(waker);

            let mut fut = timeout_at(
                Instant::now() + Duration::from_millis(1500),
                sleep(Duration::from_millis(1000)),
            );
            assert_eq!(Pin::new(&mut fut).poll(&mut cx), Poll::Pending);
            advance(Duration::from_millis(1001)).await;
            assert!(matches!(
                Pin::new(&mut fut).poll(&mut cx),
                Poll::Ready(Ok(_))
            ));
        }

        #[wasm_bindgen_test]
        async fn timeout_at_fail_test() {
            initialize();

            let waker = noop_waker_ref();
            let mut cx = Context::from_waker(waker);

            let mut fut = timeout_at(
                Instant::now() + Duration::from_millis(1000),
                sleep(Duration::from_millis(1500)),
            );
            assert_eq!(Pin::new(&mut fut).poll(&mut cx), Poll::Pending);
            advance(Duration::from_millis(1001)).await;
            assert!(matches!(
                Pin::new(&mut fut).poll(&mut cx),
                Poll::Ready(Err(_))
            ));
        }
    }

    #[cfg(feature = "tokio-util")]
    pub mod delay_queue_tests {
        use wasmtimer::tokio_util::DelayQueue;

        use super::*;

        #[wasm_bindgen_test]
        async fn insert_at_test() {
            initialize();

            let waker = noop_waker_ref();
            let mut cx = Context::from_waker(waker);

            let mut delay_queue = DelayQueue::<()>::new();
            let key1 = delay_queue.insert_at((), Instant::now() + Duration::from_millis(1000));
            let key2 = delay_queue.insert_at((), Instant::now() + Duration::from_millis(1000));
            let key3 = delay_queue.insert_at((), Instant::now() + Duration::from_millis(1500));
            advance(Duration::from_millis(1000)).await;

            let expired_1 = delay_queue.poll_expired(&mut cx);
            assert!(matches!(expired_1, Poll::Ready(Some(_))));
            if let Poll::Ready(Some(expired)) = expired_1 {
                assert_eq!(key1, expired.key());
            }

            let expired_2 = delay_queue.poll_expired(&mut cx);
            assert!(matches!(expired_2, Poll::Ready(Some(_))));
            if let Poll::Ready(Some(expired)) = expired_2 {
                assert_eq!(key2, expired.key());
            }

            assert!(matches!(delay_queue.poll_expired(&mut cx), Poll::Pending));

            advance(Duration::from_millis(500)).await;

            let expired_3 = delay_queue.poll_expired(&mut cx);
            assert!(matches!(expired_3, Poll::Ready(Some(_))));
            if let Poll::Ready(Some(expired)) = expired_3 {
                assert_eq!(key3, expired.key());
            }

            assert!(matches!(
                delay_queue.poll_expired(&mut cx),
                Poll::Ready(None)
            ));

            let key4 = delay_queue.insert_at((), Instant::now() + Duration::from_millis(500));
            advance(Duration::from_millis(500)).await;

            let expired_4 = delay_queue.poll_expired(&mut cx);
            assert!(matches!(expired_4, Poll::Ready(Some(_))));
            if let Poll::Ready(Some(expired)) = expired_4 {
                assert_eq!(key4, expired.key());
            }

            assert!(matches!(
                delay_queue.poll_expired(&mut cx),
                Poll::Ready(None)
            ));
        }

        #[wasm_bindgen_test]
        async fn insert_test() {
            initialize();

            let waker = noop_waker_ref();
            let mut cx = Context::from_waker(waker);

            let mut delay_queue = DelayQueue::<()>::new();
            let key1 = delay_queue.insert((), Duration::from_millis(1000));
            let key2 = delay_queue.insert((), Duration::from_millis(1000));
            let key3 = delay_queue.insert((), Duration::from_millis(1500));
            advance(Duration::from_millis(1000)).await;

            let expired_1 = delay_queue.poll_expired(&mut cx);
            assert!(matches!(expired_1, Poll::Ready(Some(_))));
            if let Poll::Ready(Some(expired)) = expired_1 {
                assert_eq!(key1, expired.key());
            }
            let expired_2 = delay_queue.poll_expired(&mut cx);
            assert!(matches!(expired_2, Poll::Ready(Some(_))));
            if let Poll::Ready(Some(expired)) = expired_2 {
                assert_eq!(key2, expired.key());
            }

            assert!(matches!(delay_queue.poll_expired(&mut cx), Poll::Pending));

            advance(Duration::from_millis(500)).await;

            let expired_3 = delay_queue.poll_expired(&mut cx);
            assert!(matches!(expired_3, Poll::Ready(Some(_))));
            if let Poll::Ready(Some(expired)) = expired_3 {
                assert_eq!(key3, expired.key());
            }

            assert!(matches!(
                delay_queue.poll_expired(&mut cx),
                Poll::Ready(None)
            ));

            let key4 = delay_queue.insert((), Duration::from_millis(500));
            advance(Duration::from_millis(500)).await;

            let expired_4 = delay_queue.poll_expired(&mut cx);
            assert!(matches!(expired_4, Poll::Ready(Some(_))));
            if let Poll::Ready(Some(expired)) = expired_4 {
                assert_eq!(key4, expired.key());
            }

            assert!(matches!(
                delay_queue.poll_expired(&mut cx),
                Poll::Ready(None)
            ));
        }

        #[wasm_bindgen_test]
        async fn immidiately_remove_test() {
            initialize();

            let waker = noop_waker_ref();
            let mut cx = Context::from_waker(waker);

            let mut delay_queue = DelayQueue::<()>::new();

            let key1 = delay_queue.insert((), Duration::from_millis(1000));
            delay_queue.remove(&key1);
            assert!(matches!(
                delay_queue.poll_expired(&mut cx),
                Poll::Ready(None)
            ));

            advance(Duration::from_millis(1000)).await;
            assert!(matches!(
                delay_queue.poll_expired(&mut cx),
                Poll::Ready(None)
            ));
        }

        #[wasm_bindgen_test]
        async fn remove_after_deadline_test() {
            initialize();

            let waker = noop_waker_ref();
            let mut cx = Context::from_waker(waker);

            let mut delay_queue = DelayQueue::<()>::new();

            let key1 = delay_queue.insert((), Duration::from_millis(1000));
            assert!(matches!(delay_queue.poll_expired(&mut cx), Poll::Pending));
            advance(Duration::from_millis(1000)).await;
            delay_queue.remove(&key1);
            assert!(matches!(
                delay_queue.poll_expired(&mut cx),
                Poll::Ready(None)
            ));
        }

        #[wasm_bindgen_test]
        async fn reset_test() {
            initialize();

            let waker = noop_waker_ref();
            let mut cx = Context::from_waker(waker);

            let mut delay_queue = DelayQueue::<()>::new();

            let key1 = delay_queue.insert((), Duration::from_millis(1000));
            assert!(matches!(delay_queue.poll_expired(&mut cx), Poll::Pending));
            delay_queue.reset(&key1, Duration::from_millis(1500));
            advance(Duration::from_millis(1000)).await;
            assert!(matches!(delay_queue.poll_expired(&mut cx), Poll::Pending));
            advance(Duration::from_millis(500)).await;
            assert!(matches!(
                delay_queue.poll_expired(&mut cx),
                Poll::Ready(Some(_))
            ));
            assert!(matches!(
                delay_queue.poll_expired(&mut cx),
                Poll::Ready(None)
            ));
        }
    }
}
