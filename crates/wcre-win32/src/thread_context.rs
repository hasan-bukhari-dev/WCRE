#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
compile_error!("WCRE x64 context installation currently supports Windows x86-64 only");

use std::fmt;

use wcre_image::X64ContextSubset;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::{
    CONTEXT, CONTEXT_CONTROL_AMD64, CONTEXT_FLAGS, CONTEXT_INTEGER_AMD64, GetThreadContext,
    SetThreadContext,
};

/// The x86-64 CONTEXT groups currently owned by WCRE.
///
/// M4.4 deliberately installs only the integer and control state that is
/// persisted in X64ContextSubset. Floating-point, SIMD, vector, debug-register,
/// and XSTATE state remain outside the current restore claim.
fn wcre_context_flags() -> CONTEXT_FLAGS {
    CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64
}

/// EFLAGS bits currently permitted to differ after SetThreadContext.
///
/// In the controlled M4.4 experiment Windows normalized bit 1 while preserving
/// every other persisted EFLAGS bit. WCRE remains fail-closed for any
/// difference outside this explicitly modeled mask.
pub const WINDOWS_X64_EFLAGS_NORMALIZED_MASK: u32 = 0x0000_0002;

fn eflags_match_after_set_thread_context(expected: u32, actual: u32) -> bool {
    ((expected ^ actual) & !WINDOWS_X64_EFLAGS_NORMALIZED_MASK) == 0
}

/// Storage for the native Windows x64 CONTEXT ABI.
///
/// The Windows AMD64 context APIs require suitably aligned CONTEXT storage.
/// Keeping CONTEXT as the first field makes `inner` share this 16-byte-aligned
/// address.
#[repr(C, align(16))]
struct AlignedContext {
    inner: CONTEXT,
}

impl AlignedContext {
    fn new(flags: CONTEXT_FLAGS) -> Self {
        Self {
            inner: CONTEXT {
                ContextFlags: flags,
                ..Default::default()
            },
        }
    }
}

/// One exact WCRE-owned register mismatch observed after SetThreadContext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextFieldMismatch {
    pub field: &'static str,
    pub expected: u64,
    pub actual: u64,
}

/// Verified result of installing WCRE's persisted x64 integer/control subset
/// into a stopped destination thread.
///
/// `before` is the Windows-created destination subset observed before mutation.
/// `requested` is the captured WCRE subset supplied by the caller.
/// `after` is the immediate GetThreadContext readback after SetThreadContext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationThreadContextInstallation {
    pub before: X64ContextSubset,
    pub requested: X64ContextSubset,
    pub after: X64ContextSubset,
    pub context_flags: u32,
}

/// Errors produced while observing or installing destination CPU context.
#[derive(Debug)]
pub enum DestinationThreadContextError {
    Windows {
        operation: &'static str,
        error: windows::core::Error,
    },
    Verification {
        mismatch: ContextFieldMismatch,
    },
}

impl fmt::Display for DestinationThreadContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Windows { operation, error } => {
                write!(f, "{operation} failed: {error}")
            }
            Self::Verification { mismatch } => write!(
                f,
                "destination thread context verification failed for {}: expected {:#018X}, observed {:#018X}",
                mismatch.field, mismatch.expected, mismatch.actual
            ),
        }
    }
}

impl std::error::Error for DestinationThreadContextError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Windows { error, .. } => Some(error),
            Self::Verification { .. } => None,
        }
    }
}

/// Read the WCRE-owned integer/control subset from a stopped Windows x64 thread.
pub fn query_destination_thread_context(
    thread_handle: HANDLE,
) -> Result<X64ContextSubset, DestinationThreadContextError> {
    let context = get_windows_context(thread_handle, "GetThreadContext")?;
    Ok(context_subset_from_windows(&context.inner))
}

/// Install the captured WCRE-owned register subset into a stopped destination
/// thread and immediately verify readback using WCRE's fail-closed x64 policy.
///
/// WCRE first asks Windows for the existing destination CONTEXT and mutates only
/// fields represented by X64ContextSubset. This intentionally preserves
/// destination-owned fields within the requested CONTEXT groups instead of
/// constructing a zero-filled replacement CONTEXT.
///
/// This function does not resume the thread.
pub fn install_destination_thread_context(
    thread_handle: HANDLE,
    requested: &X64ContextSubset,
) -> Result<DestinationThreadContextInstallation, DestinationThreadContextError> {
    let mut context = get_windows_context(
        thread_handle,
        "GetThreadContext before context installation",
    )?;

    let before = context_subset_from_windows(&context.inner);

    overlay_context_subset(&mut context.inner, requested);

    unsafe { SetThreadContext(thread_handle, &context.inner) }.map_err(|error| {
        DestinationThreadContextError::Windows {
            operation: "SetThreadContext",
            error,
        }
    })?;

    let after_context =
        get_windows_context(thread_handle, "GetThreadContext after context installation")?;

    let after = context_subset_from_windows(&after_context.inner);

    if let Some(mismatch) = first_context_mismatch(requested, &after) {
        return Err(DestinationThreadContextError::Verification { mismatch });
    }

    Ok(DestinationThreadContextInstallation {
        before,
        requested: requested.clone(),
        after,
        context_flags: wcre_context_flags().0,
    })
}

fn get_windows_context(
    thread_handle: HANDLE,
    operation: &'static str,
) -> Result<AlignedContext, DestinationThreadContextError> {
    let mut context = AlignedContext::new(wcre_context_flags());

    unsafe { GetThreadContext(thread_handle, &mut context.inner) }
        .map_err(|error| DestinationThreadContextError::Windows { operation, error })?;

    Ok(context)
}

fn overlay_context_subset(context: &mut CONTEXT, requested: &X64ContextSubset) {
    context.Rax = requested.rax;
    context.Rbx = requested.rbx;
    context.Rcx = requested.rcx;
    context.Rdx = requested.rdx;
    context.Rsi = requested.rsi;
    context.Rdi = requested.rdi;

    context.R8 = requested.r8;
    context.R9 = requested.r9;
    context.R10 = requested.r10;
    context.R11 = requested.r11;
    context.R12 = requested.r12;
    context.R13 = requested.r13;
    context.R14 = requested.r14;
    context.R15 = requested.r15;

    context.Rip = requested.rip;
    context.Rsp = requested.rsp;
    context.Rbp = requested.rbp;

    context.EFlags = requested.eflags;
}

fn context_subset_from_windows(context: &CONTEXT) -> X64ContextSubset {
    X64ContextSubset {
        rax: context.Rax,
        rbx: context.Rbx,
        rcx: context.Rcx,
        rdx: context.Rdx,
        rsi: context.Rsi,
        rdi: context.Rdi,

        r8: context.R8,
        r9: context.R9,
        r10: context.R10,
        r11: context.R11,
        r12: context.R12,
        r13: context.R13,
        r14: context.R14,
        r15: context.R15,

        rip: context.Rip,
        rsp: context.Rsp,
        rbp: context.Rbp,

        eflags: context.EFlags,
    }
}

fn first_context_mismatch(
    expected: &X64ContextSubset,
    actual: &X64ContextSubset,
) -> Option<ContextFieldMismatch> {
    macro_rules! check_u64 {
        ($field:ident) => {
            if expected.$field != actual.$field {
                return Some(ContextFieldMismatch {
                    field: stringify!($field),
                    expected: expected.$field,
                    actual: actual.$field,
                });
            }
        };
    }

    check_u64!(rax);
    check_u64!(rbx);
    check_u64!(rcx);
    check_u64!(rdx);
    check_u64!(rsi);
    check_u64!(rdi);

    check_u64!(r8);
    check_u64!(r9);
    check_u64!(r10);
    check_u64!(r11);
    check_u64!(r12);
    check_u64!(r13);
    check_u64!(r14);
    check_u64!(r15);

    check_u64!(rip);
    check_u64!(rsp);
    check_u64!(rbp);

    if !eflags_match_after_set_thread_context(expected.eflags, actual.eflags) {
        return Some(ContextFieldMismatch {
            field: "eflags",
            expected: u64::from(expected.eflags),
            actual: u64::from(actual.eflags),
        });
    }

    None
}

/// Compare two persisted x64 subsets using the same fail-closed policy WCRE
/// applies to SetThreadContext readback.
///
/// All 17 non-EFLAGS fields must match exactly. EFLAGS may differ only in the
/// explicitly modeled Windows-normalized mask.
pub fn x64_contexts_match_after_set_thread_context(
    expected: &X64ContextSubset,
    actual: &X64ContextSubset,
) -> bool {
    first_context_mismatch(expected, actual).is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_context() -> X64ContextSubset {
        X64ContextSubset {
            rax: 0x01,
            rbx: 0x02,
            rcx: 0x03,
            rdx: 0x04,
            rsi: 0x05,
            rdi: 0x06,

            r8: 0x08,
            r9: 0x09,
            r10: 0x0A,
            r11: 0x0B,
            r12: 0x0C,
            r13: 0x0D,
            r14: 0x0E,
            r15: 0x0F,

            rip: 0x0000_7FF6_1234_5678,
            rsp: 0x0000_0012_FFFF_E000,
            rbp: 0x0000_0012_FFFF_E100,

            eflags: 0x202,
        }
    }

    #[test]
    fn aligned_context_satisfies_windows_x64_abi_alignment() {
        assert!(std::mem::align_of::<AlignedContext>() >= 16);

        let context = AlignedContext::new(wcre_context_flags());
        let address = (&context.inner as *const CONTEXT) as usize;

        assert_eq!(address % 16, 0);
    }

    #[test]
    fn context_flags_request_control_and_integer_groups() {
        let flags = wcre_context_flags();

        assert!(flags.contains(CONTEXT_CONTROL_AMD64));
        assert!(flags.contains(CONTEXT_INTEGER_AMD64));
    }

    #[test]
    fn overlay_round_trips_every_wcre_owned_field() {
        let requested = sample_context();

        let mut windows_context = CONTEXT {
            ContextFlags: wcre_context_flags(),
            ..Default::default()
        };

        overlay_context_subset(&mut windows_context, &requested);

        assert_eq!(context_subset_from_windows(&windows_context), requested);
    }

    #[test]
    fn overlay_preserves_destination_owned_context_fields() {
        let requested = sample_context();

        let mut windows_context = CONTEXT {
            ContextFlags: wcre_context_flags(),
            MxCsr: 0x1F80,
            SegCs: 0x33,
            SegSs: 0x2B,
            P1Home: 0x1111,
            P2Home: 0x2222,
            Dr0: 0x3333,
            ..Default::default()
        };

        let original_flags = windows_context.ContextFlags;
        let original_mxcsr = windows_context.MxCsr;
        let original_seg_cs = windows_context.SegCs;
        let original_seg_ss = windows_context.SegSs;
        let original_p1_home = windows_context.P1Home;
        let original_p2_home = windows_context.P2Home;
        let original_dr0 = windows_context.Dr0;

        overlay_context_subset(&mut windows_context, &requested);

        assert_eq!(windows_context.ContextFlags, original_flags);
        assert_eq!(windows_context.MxCsr, original_mxcsr);
        assert_eq!(windows_context.SegCs, original_seg_cs);
        assert_eq!(windows_context.SegSs, original_seg_ss);
        assert_eq!(windows_context.P1Home, original_p1_home);
        assert_eq!(windows_context.P2Home, original_p2_home);
        assert_eq!(windows_context.Dr0, original_dr0);
    }

    #[test]
    fn verification_reports_the_first_exact_register_mismatch() {
        let expected = sample_context();
        let mut actual = expected.clone();

        actual.r11 ^= 0x10;

        assert_eq!(
            first_context_mismatch(&expected, &actual),
            Some(ContextFieldMismatch {
                field: "r11",
                expected: expected.r11,
                actual: actual.r11,
            })
        );
    }

    #[test]
    fn verification_allows_only_modeled_windows_eflags_normalization() {
        let expected = sample_context();
        let mut actual = expected.clone();

        // Observed in the real M4.4 SetThreadContext experiment:
        // requested 0x202, immediate GetThreadContext readback 0x200.
        actual.eflags ^= WINDOWS_X64_EFLAGS_NORMALIZED_MASK;

        assert_eq!(first_context_mismatch(&expected, &actual), None);
        assert!(x64_contexts_match_after_set_thread_context(
            &expected, &actual
        ));
    }

    #[test]
    fn verification_includes_eflags() {
        let expected = sample_context();
        let mut actual = expected.clone();

        actual.eflags ^= 0x1;

        assert_eq!(
            first_context_mismatch(&expected, &actual),
            Some(ContextFieldMismatch {
                field: "eflags",
                expected: u64::from(expected.eflags),
                actual: u64::from(actual.eflags),
            })
        );
    }
}
