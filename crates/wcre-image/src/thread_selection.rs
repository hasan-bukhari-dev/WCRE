use std::fmt;

use crate::{CheckpointModel, ImageRecord, ThreadRecord};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreadSelectionError {
    NoCandidate,
    MultipleCandidates {
        count: usize,
    },
    MissingStackBounds {
        thread_id: u32,
    },
    InvalidStackBounds {
        thread_id: u32,
        stack_limit: u64,
        stack_base: u64,
    },
    StackPointerOutsideBounds {
        thread_id: u32,
        rsp: u64,
        stack_limit: u64,
        stack_base: u64,
    },
}

impl fmt::Display for ThreadSelectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCandidate => {
                write!(
                    formatter,
                    "no captured thread has an RIP inside the selected image"
                )
            }

            Self::MultipleCandidates { count } => {
                write!(
                    formatter,
                    "{count} captured threads have RIP values inside the selected image"
                )
            }

            Self::MissingStackBounds { thread_id } => {
                write!(
                    formatter,
                    "captured thread {thread_id} does not have complete stack bounds"
                )
            }

            Self::InvalidStackBounds {
                thread_id,
                stack_limit,
                stack_base,
            } => {
                write!(
                    formatter,
                    "captured thread {thread_id} has invalid stack bounds \
                     0x{stack_limit:016X}-0x{stack_base:016X}"
                )
            }

            Self::StackPointerOutsideBounds {
                thread_id,
                rsp,
                stack_limit,
                stack_base,
            } => {
                write!(
                    formatter,
                    "captured thread {thread_id} has RSP 0x{rsp:016X} outside stack \
                     0x{stack_limit:016X}-0x{stack_base:016X}"
                )
            }
        }
    }
}

impl std::error::Error for ThreadSelectionError {}

/// Select the unique captured thread whose saved RIP belongs to `image`.
///
/// This is deliberately a checkpoint-model operation. It performs no Win32
/// calls and does not depend on capture-time thread IDs having any meaning in
/// a future destination process.
///
/// The controlled single-thread restoration policy is fail-closed:
///
/// - no matching thread is an error,
/// - more than one matching thread is an error,
/// - missing or invalid stack bounds are an error,
/// - an RSP outside the captured half-open stack range is an error.
pub fn select_unique_thread_in_image<'a>(
    checkpoint: &'a CheckpointModel,
    image: &ImageRecord,
) -> Result<&'a ThreadRecord, ThreadSelectionError> {
    let mut candidates = checkpoint.threads.iter().filter(|thread| {
        thread
            .context
            .as_ref()
            .is_some_and(|context| image.contains(context.rip))
    });

    let Some(thread) = candidates.next() else {
        return Err(ThreadSelectionError::NoCandidate);
    };

    let additional_candidates = candidates.count();

    if additional_candidates != 0 {
        return Err(ThreadSelectionError::MultipleCandidates {
            count: additional_candidates + 1,
        });
    }

    let context = thread
        .context
        .as_ref()
        .expect("selected candidate necessarily has captured context");

    let (Some(stack_limit), Some(stack_base)) = (thread.stack_limit, thread.stack_base) else {
        return Err(ThreadSelectionError::MissingStackBounds {
            thread_id: thread.thread_id,
        });
    };

    if stack_limit >= stack_base {
        return Err(ThreadSelectionError::InvalidStackBounds {
            thread_id: thread.thread_id,
            stack_limit,
            stack_base,
        });
    }

    if context.rsp < stack_limit || context.rsp >= stack_base {
        return Err(ThreadSelectionError::StackPointerOutsideBounds {
            thread_id: thread.thread_id,
            rsp: context.rsp,
            stack_limit,
            stack_base,
        });
    }

    Ok(thread)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Architecture, CheckpointModel, ImageRecord, ProcessRecord, ThreadRecord, X64ContextSubset,
    };

    const IMAGE_BASE: u64 = 0x0000_7FF7_0000_0000;
    const IMAGE_SIZE: u32 = 0x20_000;
    const STACK_LIMIT: u64 = 0x0000_0012_000F_0000;
    const STACK_BASE: u64 = 0x0000_0012_0010_0000;

    fn checkpoint() -> CheckpointModel {
        CheckpointModel::new(ProcessRecord {
            captured_pid: 42,
            architecture: Architecture::X64,
            image_path: r"C:\example\target.exe".to_string(),
        })
    }

    fn image() -> ImageRecord {
        ImageRecord {
            loaded_base: IMAGE_BASE,
            preferred_image_base: 0x0000_0001_4000_0000,
            size_of_image: IMAGE_SIZE,
            time_date_stamp: 0,
            checksum: 0,
            mapped_path: Some(r"C:\example\target.exe".to_string()),
        }
    }

    fn context(rip: u64, rsp: u64) -> X64ContextSubset {
        X64ContextSubset {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip,
            rsp,
            rbp: 0,
            eflags: 0x202,
        }
    }

    fn thread(thread_id: u32, rip: u64, rsp: u64) -> ThreadRecord {
        ThreadRecord {
            process_id: 42,
            thread_id,
            teb_base_address: 0x0000_0012_0000_0000 + u64::from(thread_id) * 0x1000,
            stack_base: Some(STACK_BASE),
            stack_limit: Some(STACK_LIMIT),
            context: Some(context(rip, rsp)),
        }
    }

    #[test]
    fn selects_unique_thread_whose_rip_is_inside_image() {
        let mut checkpoint = checkpoint();
        let image = image();

        checkpoint
            .threads
            .push(thread(100, 0x0000_7FFF_0000_1000, STACK_LIMIT + 0x1000));
        checkpoint
            .threads
            .push(thread(200, IMAGE_BASE + 0x1234, STACK_LIMIT + 0x2000));

        let selected = select_unique_thread_in_image(&checkpoint, &image).unwrap();

        assert_eq!(selected.thread_id, 200);
    }

    #[test]
    fn rejects_checkpoint_with_no_candidate() {
        let mut checkpoint = checkpoint();
        let image = image();

        checkpoint
            .threads
            .push(thread(100, 0x0000_7FFF_0000_1000, STACK_LIMIT + 0x1000));

        assert_eq!(
            select_unique_thread_in_image(&checkpoint, &image),
            Err(ThreadSelectionError::NoCandidate)
        );
    }

    #[test]
    fn rejects_checkpoint_with_multiple_candidates() {
        let mut checkpoint = checkpoint();
        let image = image();

        checkpoint
            .threads
            .push(thread(100, IMAGE_BASE + 0x1000, STACK_LIMIT + 0x1000));
        checkpoint
            .threads
            .push(thread(200, IMAGE_BASE + 0x2000, STACK_LIMIT + 0x2000));

        assert_eq!(
            select_unique_thread_in_image(&checkpoint, &image),
            Err(ThreadSelectionError::MultipleCandidates { count: 2 })
        );
    }

    #[test]
    fn thread_without_context_is_not_a_candidate() {
        let mut checkpoint = checkpoint();
        let image = image();

        checkpoint.threads.push(ThreadRecord {
            process_id: 42,
            thread_id: 100,
            teb_base_address: 0x1000,
            stack_base: Some(STACK_BASE),
            stack_limit: Some(STACK_LIMIT),
            context: None,
        });

        checkpoint
            .threads
            .push(thread(200, IMAGE_BASE + 0x1000, STACK_LIMIT + 0x1000));

        let selected = select_unique_thread_in_image(&checkpoint, &image).unwrap();

        assert_eq!(selected.thread_id, 200);
    }

    #[test]
    fn rejects_selected_thread_with_missing_stack_bounds() {
        let mut checkpoint = checkpoint();
        let image = image();

        let mut candidate = thread(100, IMAGE_BASE + 0x1000, STACK_LIMIT + 0x1000);
        candidate.stack_limit = None;

        checkpoint.threads.push(candidate);

        assert_eq!(
            select_unique_thread_in_image(&checkpoint, &image),
            Err(ThreadSelectionError::MissingStackBounds { thread_id: 100 })
        );
    }

    #[test]
    fn rejects_selected_thread_with_invalid_stack_bounds() {
        let mut checkpoint = checkpoint();
        let image = image();

        let mut candidate = thread(100, IMAGE_BASE + 0x1000, STACK_LIMIT + 0x1000);
        candidate.stack_limit = Some(STACK_BASE);

        checkpoint.threads.push(candidate);

        assert_eq!(
            select_unique_thread_in_image(&checkpoint, &image),
            Err(ThreadSelectionError::InvalidStackBounds {
                thread_id: 100,
                stack_limit: STACK_BASE,
                stack_base: STACK_BASE,
            })
        );
    }

    #[test]
    fn stack_range_is_half_open() {
        let image = image();

        let mut valid_checkpoint = checkpoint();
        valid_checkpoint
            .threads
            .push(thread(100, IMAGE_BASE + 0x1000, STACK_LIMIT));

        assert!(select_unique_thread_in_image(&valid_checkpoint, &image).is_ok());

        let mut invalid_checkpoint = checkpoint();
        invalid_checkpoint
            .threads
            .push(thread(100, IMAGE_BASE + 0x1000, STACK_BASE));

        assert_eq!(
            select_unique_thread_in_image(&invalid_checkpoint, &image),
            Err(ThreadSelectionError::StackPointerOutsideBounds {
                thread_id: 100,
                rsp: STACK_BASE,
                stack_limit: STACK_LIMIT,
                stack_base: STACK_BASE,
            })
        );
    }

    #[test]
    fn image_range_is_half_open() {
        let image = image();

        let mut lower_boundary = checkpoint();
        lower_boundary
            .threads
            .push(thread(100, IMAGE_BASE, STACK_LIMIT + 0x1000));

        assert!(select_unique_thread_in_image(&lower_boundary, &image).is_ok());

        let mut upper_boundary = checkpoint();
        upper_boundary.threads.push(thread(
            100,
            IMAGE_BASE + u64::from(IMAGE_SIZE),
            STACK_LIMIT + 0x1000,
        ));

        assert_eq!(
            select_unique_thread_in_image(&upper_boundary, &image),
            Err(ThreadSelectionError::NoCandidate)
        );
    }

    #[test]
    fn rejects_rsp_below_stack_limit() {
        let mut checkpoint = checkpoint();
        let image = image();

        checkpoint
            .threads
            .push(thread(100, IMAGE_BASE + 0x1000, STACK_LIMIT - 8));

        assert_eq!(
            select_unique_thread_in_image(&checkpoint, &image),
            Err(ThreadSelectionError::StackPointerOutsideBounds {
                thread_id: 100,
                rsp: STACK_LIMIT - 8,
                stack_limit: STACK_LIMIT,
                stack_base: STACK_BASE,
            })
        );
    }
}
