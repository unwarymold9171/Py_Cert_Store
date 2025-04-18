// Copyright 2025 Niky H. (Unwarymold9171)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

#![cfg(windows)]

macro_rules! inner_impl {
    ($t:path, $inner:ty) => {
        impl crate::windows_store::Inner<$inner> for $t {
            unsafe fn from_inner(t: $inner) -> Self {
                $t(t)
            }

            fn as_inner(&self) -> $inner {
                self.0
            }

            fn get_mut(&mut self) -> &mut $inner {
                &mut self.0
            }
        }
    };
}

pub mod cert_context;
pub mod cert_store;

trait Inner<T> {
    unsafe fn from_inner(t: T) -> Self;

    fn as_inner(&self) -> T;

    #[allow(dead_code)]
    fn get_mut(&mut self) -> &mut T;
}
