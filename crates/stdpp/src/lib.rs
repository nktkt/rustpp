pub use rustpp_attributes::{component, contract, effects, ensures, requires, unsafe_boundary};

pub mod asyncx {
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    pub fn block_on<F: Future>(future: F) -> F::Output {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = std::pin::pin!(future);

        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }
}

pub mod audit {
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct UnsafeBoundary {
        pub name: &'static str,
        pub reason: &'static str,
        pub audit: &'static str,
    }

    impl UnsafeBoundary {
        pub const fn new(name: &'static str, reason: &'static str, audit: &'static str) -> Self {
            Self {
                name,
                reason,
                audit,
            }
        }
    }
}

pub mod component {
    pub trait Component {
        fn name(&self) -> &'static str {
            std::any::type_name::<Self>()
        }
    }

    impl<T> Component for T {}
}

pub mod contract {
    use std::fmt;
    use std::ops::Deref;

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct ContractError {
        message: String,
    }

    impl ContractError {
        pub fn new(message: impl Into<String>) -> Self {
            Self {
                message: message.into(),
            }
        }

        pub fn message(&self) -> &str {
            &self.message
        }
    }

    impl fmt::Display for ContractError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.message)
        }
    }

    impl std::error::Error for ContractError {}

    pub trait Predicate<T> {
        fn check(value: &T) -> bool;
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Refined<T, P> {
        value: T,
        _predicate: std::marker::PhantomData<P>,
    }

    impl<T, P: Predicate<T>> Refined<T, P> {
        pub fn new(value: T) -> Result<Self, ContractError> {
            if P::check(&value) {
                Ok(Self {
                    value,
                    _predicate: std::marker::PhantomData,
                })
            } else {
                Err(ContractError::new("refinement predicate failed"))
            }
        }

        pub fn get(&self) -> &T {
            &self.value
        }

        pub fn into_inner(self) -> T {
            self.value
        }
    }

    impl<T, P> AsRef<T> for Refined<T, P> {
        fn as_ref(&self) -> &T {
            &self.value
        }
    }

    impl<T, P> Deref for Refined<T, P> {
        type Target = T;

        fn deref(&self) -> &Self::Target {
            &self.value
        }
    }
}

#[macro_export]
macro_rules! refined_type {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident($inner:ty) where |$value:ident| $predicate:expr, $message:expr $(;)?
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
        $vis struct $name($inner);

        impl $name {
            pub fn new(value: $inner) -> ::std::result::Result<Self, $crate::contract::ContractError> {
                let $value: &$inner = &value;
                if $predicate {
                    Ok(Self(value))
                } else {
                    Err($crate::contract::ContractError::new($message))
                }
            }

            pub fn get(&self) -> &$inner {
                &self.0
            }

            pub fn into_inner(self) -> $inner {
                self.0
            }
        }

        impl ::std::convert::TryFrom<$inner> for $name {
            type Error = $crate::contract::ContractError;

            fn try_from(value: $inner) -> ::std::result::Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl ::std::convert::AsRef<$inner> for $name {
            fn as_ref(&self) -> &$inner {
                self.get()
            }
        }

        impl ::std::ops::Deref for $name {
            type Target = $inner;

            fn deref(&self) -> &Self::Target {
                self.get()
            }
        }
    };
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident($inner:ty) where |$value:ident| $predicate:expr $(;)?
    ) => {
        $crate::refined_type! {
            $(#[$meta])*
            $vis struct $name($inner) where |$value| $predicate,
            concat!("refinement predicate failed for ", stringify!($name));
        }
    };
}

pub mod effect {
    use std::fmt;

    pub trait Capability {
        const NAME: &'static str;
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Effect {
        name: &'static str,
    }

    impl Effect {
        pub const fn new(name: &'static str) -> Self {
            Self { name }
        }

        pub const fn name(&self) -> &'static str {
            self.name
        }
    }

    impl fmt::Display for Effect {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.name)
        }
    }
}

#[macro_export]
macro_rules! capability {
    ($(#[$meta:meta])* $vis:vis $name:ident $(;)?) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
        $vis struct $name;

        impl $crate::effect::Capability for $name {
            const NAME: &'static str = stringify!($name);
        }

        impl From<$name> for $crate::effect::Effect {
            fn from(_: $name) -> Self {
                $crate::effect::Effect::new(<$name as $crate::effect::Capability>::NAME)
            }
        }
    };
}

pub mod ffi {
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct SafeFfi<T> {
        inner: T,
        boundary: &'static str,
    }

    impl<T> SafeFfi<T> {
        pub fn new(inner: T, boundary: &'static str) -> Self {
            Self { inner, boundary }
        }

        pub fn boundary(&self) -> &'static str {
            self.boundary
        }

        pub fn into_inner(self) -> T {
            self.inner
        }
    }
}

pub mod policy {
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Policy {
        name: &'static str,
        denied_effects: &'static [&'static str],
    }

    impl Policy {
        pub const fn new(name: &'static str, denied_effects: &'static [&'static str]) -> Self {
            Self {
                name,
                denied_effects,
            }
        }

        pub const fn name(&self) -> &'static str {
            self.name
        }

        pub fn denies(&self, effect: &str) -> bool {
            self.denied_effects.contains(&effect)
        }
    }
}

pub mod prelude {
    pub use crate::component::Component;
    pub use crate::contract::{ContractError, Predicate, Refined};
    pub use crate::effect::{Capability, Effect};
    pub use crate::policy::Policy;
    pub use crate::{asyncx, audit, capability, ffi, refined_type};
    pub use rustpp_attributes::{component, contract, effects, ensures, requires, unsafe_boundary};
}
