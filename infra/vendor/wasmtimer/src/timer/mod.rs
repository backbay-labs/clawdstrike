// The `timer` module is a copy-paste from the code of `futures-timer`, but
// adjusted for WASM.
//
// Copyright (c) 2014 Alex Crichton
//
// Permission is hereby granted, free of charge, to any
// person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the
// Software without restriction, including without
// limitation the rights to use, copy, modify, merge,
// publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software
// is furnished to do so, subject to the following
// conditions:
//
// The above copyright notice and this permission notice
// shall be included in all copies or substantial portions
// of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
// ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
// TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
// PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
// SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
// IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
//
// Apache License
// Version 2.0, January 2004
// http://www.apache.org/licenses/
//
// TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION
//
// 1. Definitions.
//
// "License" shall mean the terms and conditions for use, reproduction,
// and distribution as defined by Sections 1 through 9 of this document.
//
// "Licensor" shall mean the copyright owner or entity authorized by
// the copyright owner that is granting the License.
//
// "Legal Entity" shall mean the union of the acting entity and all
// other entities that control, are controlled by, or are under common
// control with that entity. For the purposes of this definition,
// "control" means (i) the power, direct or indirect, to cause the
// direction or management of such entity, whether by contract or
// otherwise, or (ii) ownership of fifty percent (50%) or more of the
// outstanding shares, or (iii) beneficial ownership of such entity.
//
// "You" (or "Your") shall mean an individual or Legal Entity
// exercising permissions granted by this License.
//
// "Source" form shall mean the preferred form for making modifications,
// including but not limited to software source code, documentation
// source, and configuration files.
//
// "Object" form shall mean any form resulting from mechanical
// transformation or translation of a Source form, including but
// not limited to compiled object code, generated documentation,
// and conversions to other media types.
//
// "Work" shall mean the work of authorship, whether in Source or
// Object form, made available under the License, as indicated by a
// copyright notice that is included in or attached to the work
// (an example is provided in the Appendix below).
//
// "Derivative Works" shall mean any work, whether in Source or Object
// form, that is based on (or derived from) the Work and for which the
// editorial revisions, annotations, elaborations, or other modifications
// represent, as a whole, an original work of authorship. For the purposes
// of this License, Derivative Works shall not include works that remain
// separable from, or merely link (or bind by name) to the interfaces of,
// the Work and Derivative Works thereof.
//
// "Contribution" shall mean any work of authorship, including
// the original version of the Work and any modifications or additions
// to that Work or Derivative Works thereof, that is intentionally
// submitted to Licensor for inclusion in the Work by the copyright owner
// or by an individual or Legal Entity authorized to submit on behalf of
// the copyright owner. For the purposes of this definition, "submitted"
// means any form of electronic, verbal, or written communication sent
// to the Licensor or its representatives, including but not limited to
// communication on electronic mailing lists, source code control systems,
// and issue tracking systems that are managed by, or on behalf of, the
// Licensor for the purpose of discussing and improving the Work, but
// excluding communication that is conspicuously marked or otherwise
// designated in writing by the copyright owner as "Not a Contribution."
//
// "Contributor" shall mean Licensor and any individual or Legal Entity
// on behalf of whom a Contribution has been received by Licensor and
// subsequently incorporated within the Work.
//
// 2. Grant of Copyright License. Subject to the terms and conditions of
// this License, each Contributor hereby grants to You a perpetual,
// worldwide, non-exclusive, no-charge, royalty-free, irrevocable
// copyright license to reproduce, prepare Derivative Works of,
// publicly display, publicly perform, sublicense, and distribute the
// Work and such Derivative Works in Source or Object form.
//
// 3. Grant of Patent License. Subject to the terms and conditions of
// this License, each Contributor hereby grants to You a perpetual,
// worldwide, non-exclusive, no-charge, royalty-free, irrevocable
// (except as stated in this section) patent license to make, have made,
// use, offer to sell, sell, import, and otherwise transfer the Work,
// where such license applies only to those patent claims licensable
// by such Contributor that are necessarily infringed by their
// Contribution(s) alone or by combination of their Contribution(s)
// with the Work to which such Contribution(s) was submitted. If You
// institute patent litigation against any entity (including a
// cross-claim or counterclaim in a lawsuit) alleging that the Work
// or a Contribution incorporated within the Work constitutes direct
// or contributory patent infringement, then any patent licenses
// granted to You under this License for that Work shall terminate
// as of the date such litigation is filed.
//
// 4. Redistribution. You may reproduce and distribute copies of the
// Work or Derivative Works thereof in any medium, with or without
// modifications, and in Source or Object form, provided that You
// meet the following conditions:
//
// (a) You must give any other recipients of the Work or
// Derivative Works a copy of this License; and
//
// (b) You must cause any modified files to carry prominent notices
// stating that You changed the files; and
//
// (c) You must retain, in the Source form of any Derivative Works
// that You distribute, all copyright, patent, trademark, and
// attribution notices from the Source form of the Work,
// excluding those notices that do not pertain to any part of
// the Derivative Works; and
//
// (d) If the Work includes a "NOTICE" text file as part of its
// distribution, then any Derivative Works that You distribute must
// include a readable copy of the attribution notices contained
// within such NOTICE file, excluding those notices that do not
// pertain to any part of the Derivative Works, in at least one
// of the following places: within a NOTICE text file distributed
// as part of the Derivative Works; within the Source form or
// documentation, if provided along with the Derivative Works; or,
// within a display generated by the Derivative Works, if and
// wherever such third-party notices normally appear. The contents
// of the NOTICE file are for informational purposes only and
// do not modify the License. You may add Your own attribution
// notices within Derivative Works that You distribute, alongside
// or as an addendum to the NOTICE text from the Work, provided
// that such additional attribution notices cannot be construed
// as modifying the License.
//
// You may add Your own copyright statement to Your modifications and
// may provide additional or different license terms and conditions
// for use, reproduction, or distribution of Your modifications, or
// for any such Derivative Works as a whole, provided Your use,
// reproduction, and distribution of the Work otherwise complies with
// the conditions stated in this License.
//
// 5. Submission of Contributions. Unless You explicitly state otherwise,
// any Contribution intentionally submitted for inclusion in the Work
// by You to the Licensor shall be under the terms and conditions of
// this License, without any additional terms or conditions.
// Notwithstanding the above, nothing herein shall supersede or modify
// the terms of any separate license agreement you may have executed
// with Licensor regarding such Contributions.
//
// 6. Trademarks. This License does not grant permission to use the trade
// names, trademarks, service marks, or product names of the Licensor,
// except as required for reasonable and customary use in describing the
// origin of the Work and reproducing the content of the NOTICE file.
//
// 7. Disclaimer of Warranty. Unless required by applicable law or
// agreed to in writing, Licensor provides the Work (and each
// Contributor provides its Contributions) on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied, including, without limitation, any warranties or conditions
// of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
// PARTICULAR PURPOSE. You are solely responsible for determining the
// appropriateness of using or redistributing the Work and assume any
// risks associated with Your exercise of permissions under this License.
//
// 8. Limitation of Liability. In no event and under no legal theory,
// whether in tort (including negligence), contract, or otherwise,
// unless required by applicable law (such as deliberate and grossly
// negligent acts) or agreed to in writing, shall any Contributor be
// liable to You for damages, including any direct, indirect, special,
// incidental, or consequential damages of any character arising as a
// result of this License or out of the use or inability to use the
// Work (including but not limited to damages for loss of goodwill,
// work stoppage, computer failure or malfunction, or any and all
// other commercial damages or losses), even if such Contributor
// has been advised of the possibility of such damages.
//
// 9. Accepting Warranty or Additional Liability. While redistributing
// the Work or Derivative Works thereof, You may choose to offer,
// and charge a fee for, acceptance of support, warranty, indemnity,
// or other liability obligations and/or rights consistent with this
// License. However, in accepting such obligations, You may act only
// on Your own behalf and on Your sole responsibility, not on behalf
// of any other Contributor, and only if You agree to indemnify,
// defend, and hold each Contributor harmless for any liability
// incurred by, or claims asserted against, such Contributor by reason
// of your accepting any such warranty or additional liability.
//
// END OF TERMS AND CONDITIONS
//
// APPENDIX: How to apply the Apache License to your work.
//
// To apply the Apache License to your work, attach the following
// boilerplate notice, with the fields enclosed by brackets "[]"
// replaced with your own identifying information. (Don't include
// the brackets!)  The text should be enclosed in the appropriate
// comment syntax for the file format. We also recommend that a
// file or class name and description of purpose be included on the
// same "printed page" as the copyright notice for easier
// identification within third-party archives.
//
// Copyright [yyyy] [name of copyright owner]
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::std::Instant;
use std::cmp::Ordering;
use std::fmt;
use std::pin::Pin;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::atomic::{AtomicPtr, AtomicUsize};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};

use futures::prelude::*;
use futures::task::AtomicWaker;

use arc_list::{ArcList, Node};
use heap::{Heap, Slot};

pub mod arc_list;
#[cfg(feature = "tokio-test-util")]
pub mod clock;
mod global;
mod heap;

/// A "timer heap" used to power separately owned instances of `Delay` and
/// `Interval`.
///
/// This timer is implemented as a priority queued-based heap. Each `Timer`
/// contains a few primary methods which which to drive it:
///
/// * `next_wake` indicates how long the ambient system needs to sleep until it
///   invokes further processing on a `Timer`
/// * `advance_to` is what actually fires timers on the `Timer`, and should be
///   called essentially every iteration of the event loop, or when the time
///   specified by `next_wake` has elapsed.
/// * The `Future` implementation for `Timer` is used to process incoming timer
///   updates and requests. This is used to schedule new timeouts, update
///   existing ones, or delete existing timeouts. The `Future` implementation
///   will never resolve, but it'll schedule notifications of when to wake up
///   and process more messages.
///
/// Note that if you're using this crate you probably don't need to use a
/// `Timer` as there is a global one already available for you run on a helper
/// thread. If this isn't desirable, though, then the
/// `TimerHandle::set_fallback` method can be used instead!
pub struct Timer {
    inner: Arc<Inner>,
    timer_heap: Heap<HeapTimer>,
}

/// A handle to a `Timer` which is used to create instances of a `Delay`.
#[derive(Clone)]
pub struct TimerHandle {
    pub inner: Weak<Inner>,
}

pub struct Inner {
    /// List of updates the `Timer` needs to process
    pub list: ArcList<ScheduledTimer>,

    /// The blocked `Timer` task to receive notifications to the `list` above.
    pub waker: AtomicWaker,
}

/// Shared state between the `Timer` and a `Delay`.
pub struct ScheduledTimer {
    pub waker: AtomicWaker,

    // The lowest bit here is whether the timer has fired or not, the second
    // lowest bit is whether the timer has been invalidated, and all the other
    // bits are the "generation" of the timer which is reset during the `reset`
    // function. Only timers for a matching generation are fired.
    pub state: AtomicUsize,

    pub inner: Weak<Inner>,
    pub at: Mutex<Option<Instant>>,

    // TODO: this is only accessed by the timer thread, should have a more
    // lightweight protection than a `Mutex`
    pub slot: Mutex<Option<Slot>>,
}

/// Entries in the timer heap, sorted by the instant they're firing at and then
/// also containing some payload data.
struct HeapTimer {
    at: Instant,
    gen: usize,
    node: Arc<Node<ScheduledTimer>>,
}

impl Timer {
    /// Creates a new timer heap ready to create new timers.
    pub fn new() -> Timer {
        Timer {
            inner: Arc::new(Inner {
                list: ArcList::new(),
                waker: AtomicWaker::new(),
            }),
            timer_heap: Heap::new(),
        }
    }

    /// Returns a handle to this timer heap, used to create new timeouts.
    pub fn handle(&self) -> TimerHandle {
        TimerHandle {
            inner: Arc::downgrade(&self.inner),
        }
    }

    /// Returns the time at which this timer next needs to be invoked with
    /// `advance_to`.
    ///
    /// Event loops or threads typically want to sleep until the specified
    /// instant.
    pub fn next_event(&self) -> Option<Instant> {
        self.timer_heap.peek().map(|t| t.at)
    }

    /// Proces any timers which are supposed to fire before `now` specified.
    ///
    /// This method should be called on `Timer` periodically to advance the
    /// internal state and process any pending timers which need to fire.
    pub fn advance_to(&mut self, now: Instant) {
        loop {
            match self.timer_heap.peek() {
                Some(head) if head.at <= now => {}
                Some(_) => break,
                None => break,
            };

            // Flag the timer as fired and then notify its task, if any, that's
            // blocked.
            let heap_timer = self.timer_heap.pop().unwrap();
            *heap_timer.node.slot.lock().unwrap() = None;
            let bits = heap_timer.gen << 2;
            match heap_timer
                .node
                .state
                .compare_exchange(bits, bits | 0b01, SeqCst, SeqCst)
            {
                Ok(_) => heap_timer.node.waker.wake(),
                Err(_b) => {}
            }
        }
    }

    /// Either updates the timer at slot `idx` to fire at `at`, or adds a new
    /// timer at `idx` and sets it to fire at `at`.
    fn update_or_add(&mut self, at: Instant, node: Arc<Node<ScheduledTimer>>) {
        // TODO: avoid remove + push and instead just do one sift of the heap?
        // In theory we could update it in place and then do the percolation
        // as necessary
        let gen = node.state.load(SeqCst) >> 2;
        let mut slot = node.slot.lock().unwrap();
        if let Some(heap_slot) = slot.take() {
            self.timer_heap.remove(heap_slot);
        }
        *slot = Some(self.timer_heap.push(HeapTimer {
            at,
            gen,
            node: node.clone(),
        }));
    }

    fn remove(&mut self, node: Arc<Node<ScheduledTimer>>) {
        // If this `idx` is still around and it's still got a registered timer,
        // then we jettison it form the timer heap.
        let mut slot = node.slot.lock().unwrap();
        let heap_slot = match slot.take() {
            Some(slot) => slot,
            None => return,
        };
        self.timer_heap.remove(heap_slot);
    }

    fn invalidate(&mut self, node: Arc<Node<ScheduledTimer>>) {
        node.state.fetch_or(0b10, SeqCst);
        node.waker.wake();
    }
}

impl Future for Timer {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.inner).waker.register(cx.waker());
        let mut list = self.inner.list.take();
        while let Some(node) = list.pop() {
            let at = *node.at.lock().unwrap();
            match at {
                Some(at) => self.update_or_add(at, node),
                None => self.remove(node),
            }
        }
        Poll::Pending
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        // Seal off our list to prevent any more updates from getting pushed on.
        // Any timer which sees an error from the push will immediately become
        // inert.
        let mut list = self.inner.list.take_and_seal();

        // Now that we'll never receive another timer, drain the list of all
        // updates and also drain our heap of all active timers, invalidating
        // everything.
        while let Some(t) = list.pop() {
            self.invalidate(t);
        }
        while let Some(t) = self.timer_heap.pop() {
            self.invalidate(t.node);
        }
    }
}

impl fmt::Debug for Timer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("Timer").field("heap", &"...").finish()
    }
}

impl PartialEq for HeapTimer {
    fn eq(&self, other: &HeapTimer) -> bool {
        self.at == other.at
    }
}

impl Eq for HeapTimer {}

impl PartialOrd for HeapTimer {
    fn partial_cmp(&self, other: &HeapTimer) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HeapTimer {
    fn cmp(&self, other: &HeapTimer) -> Ordering {
        self.at.cmp(&other.at)
    }
}

pub(crate) static HANDLE_FALLBACK: AtomicPtr<Inner> = AtomicPtr::new(EMPTY_HANDLE);
const EMPTY_HANDLE: *mut Inner = std::ptr::null_mut();

/// Error returned from `TimerHandle::set_fallback`.
#[derive(Clone, Debug)]
pub struct SetDefaultError(());

impl TimerHandle {
    /// Configures this timer handle to be the one returned by
    /// `TimerHandle::default`.
    ///
    /// By default a global thread is initialized on the first call to
    /// `TimerHandle::default`. This first call can happen transitively through
    /// `Delay::new`. If, however, that hasn't happened yet then the global
    /// default timer handle can be configured through this method.
    ///
    /// This method can be used to prevent the global helper thread from
    /// spawning. If this method is successful then the global helper thread
    /// will never get spun up.
    ///
    /// On success this timer handle will have installed itself globally to be
    /// used as the return value for `TimerHandle::default` unless otherwise
    /// specified.
    ///
    /// # Errors
    ///
    /// If another thread has already called `set_as_global_fallback` or this
    /// thread otherwise loses a race to call this method then it will fail
    /// returning an error. Once a call to `set_as_global_fallback` is
    /// successful then no future calls may succeed.
    pub fn set_as_global_fallback(self) -> Result<(), SetDefaultError> {
        unsafe {
            let val = self.into_raw();
            match HANDLE_FALLBACK.compare_exchange(EMPTY_HANDLE, val, SeqCst, SeqCst) {
                Ok(_) => Ok(()),
                Err(_) => {
                    drop(TimerHandle::from_raw(val));
                    Err(SetDefaultError(()))
                }
            }
        }
    }

    fn into_raw(self) -> *mut Inner {
        self.inner.into_raw() as *mut Inner
    }

    unsafe fn from_raw(raw: *mut Inner) -> TimerHandle {
        let inner = Weak::from_raw(raw);
        TimerHandle { inner }
    }
}

impl Default for TimerHandle {
    fn default() -> TimerHandle {
        let mut fallback = HANDLE_FALLBACK.load(SeqCst);

        // If the fallback hasn't been previously initialized then let's spin
        // up a helper thread and try to initialize with that. If we can't
        // actually create a helper thread then we'll just return a "defunkt"
        // handle which will return errors when timer objects are attempted to
        // be associated.
        if fallback == EMPTY_HANDLE {
            let handle = global::run();

            // If we successfully set ourselves as the actual fallback then we
            // want to `forget` the helper thread to ensure that it persists
            // globally. If we fail to set ourselves as the fallback that means
            // that someone was racing with this call to
            // `TimerHandle::default`.  They ended up winning so we'll destroy
            // our helper thread (which shuts down the thread) and reload the
            // fallback.
            if handle.clone().set_as_global_fallback().is_ok() {
                return handle;
            }
            fallback = HANDLE_FALLBACK.load(SeqCst);
        }

        // At this point our fallback handle global was configured so we use
        // its value to reify a handle, clone it, and then forget our reified
        // handle as we don't actually have an owning reference to it.
        assert!(fallback != EMPTY_HANDLE);
        unsafe {
            let handle = TimerHandle::from_raw(fallback);
            let ret = handle.clone();
            let _ = handle.into_raw();
            ret
        }
    }
}

impl fmt::Debug for TimerHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("TimerHandle")
            .field("inner", &"...")
            .finish()
    }
}
