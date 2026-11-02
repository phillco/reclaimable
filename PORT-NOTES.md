# Port notes

Original `0d3d303c`: unchanged implementation, packaging and 75 cases in `python/`.
Updated `0c9ff4a4`: unchanged reference and 183 collected cases (182 passed,
one filesystem-dependent skip here) in `python/upstream/`. All 142 updated
Python functions and every parameter case are mapped below, including all original
tests. No binary is committed.

## Deviations

- Scheduled native cache-maintenance hooks and the `maintenance` command are a
  Go-only addition, with no Python counterpart. They use config-only argv,
  independent opt-in/cadence and the sweep lock; fake-command tests cover guards,
  timeouts, arming and measured space reports. The Python snapshots stay frozen.
- Go 1.22+, one vendored library: `github.com/BurntSushi/toml` v1.4.0. Generated
  Unicode data is pinned to 16.0.0 and has its included license; another Python
  Unicode database can differ for newly assigned characters.
- Help/parser/OS/JSON diagnostics, JSON key order and escaping differ. Flags,
  TOML keys, marker/state schemas and ordinary command exits match.
- Malformed lease/claim objects or holder-directory settings keep data instead
  of raising exceptions. Invalid/nonfinite arming times and descendant stat errors
  keep data; overflowing sizes are rejected. File/directory changes during hash
  inventories veto verification. Timeouts bound process groups/pipes.
- Descriptor operations support macOS/Linux on amd64/arm64; other architectures
  fail closed. Linux symlink inspection uses pinned parent descriptors via procfs;
  unavailable inspection keeps the source.
- Quarantine uses random names and atomic exclusive renames, including rollback.
  Existing destinations are preserved; unsupported kernel/filesystem operations
  keep data rather than falling back to an overwriting rename.
- Local copies preserve full mode bits/macOS flags; the updated Python snapshot
  retains ordinary permission bits. Both refuse unverifiable extended payloads
  (including resource forks), except system provenance.
- Go exports verified TAR directly into an unlinked temporary descriptor; Python
  first builds a private filesystem snapshot. Both verify before sending to the
  same remote Python receiver and comparing its JSON manifest. Malformed/duplicate
  inventories are refused. Local runtime needs no Python; remote endpoints need it.
- The unreadable-claim fixture removes its earlier matching lease to reach the
  intended claim-directory check; Python's assertion can be masked by that lease.

Public module `github.com/phillco/reclaimable` and generic `/Users` safety literals
are approved text-audit exceptions. No personal fixtures/infrastructure are needed.

## Validation scope

31 subprocess parity scenarios compare exits, stdout/stderr, marker/data files,
registry, sweep records and logs. Only fixture roots, clock readings, log stamps
and current capacity are normalized. Destructive targets and outside-tree race
sentinels are temporary. Remote tests use local shell/Python shims, with no remote
host contacted. Go 1.22.12/current Go tests run on macOS arm64; Linux amd64/arm64
cross-compile only (runtime unverified). Unicode matches 29,379 differential cases.

Additional regressions cover canonical volume-floor lookup during planning and
ignored directory symlinks in JJ/Git checkouts. These match the updated reference.
Safety walks also reject child-directory replacement after descent; JJ metadata
pruning folds root names while keeping symlink entries subject to tracked checks.
Quarantine regressions cover existing directories, files, dangling symlinks,
name collisions, successful renames, and source recreation before rollback.

## Python to Go test mapping

| Python function | Go test |
| --- | --- |
| `test_removal_child_swap_never_follows_symlink` | `TestRemovalChildSwapNeverFollowsSymlink` (descriptor_safety_test.go) |
| `test_hasher_child_swap_never_reads_symlink_target` | `TestHasherChildSwapNeverReadsSymlinkTarget` (descriptor_safety_test.go) |
| `test_copy_child_swap_never_copies_symlink_target` | `TestCopyChildSwapNeverCopiesSymlinkTarget` (descriptor_safety_test.go) |
| `test_hasher_file_swap_never_reads_symlink_target` | `TestHasherFileSwapNeverReadsSymlinkTarget` (descriptor_safety_test.go) |
| `test_hasher_refuses_special_files` | `TestHasherRefusesSpecialFiles` (descriptor_safety_test.go) |
| `test_marker_swap_never_bypasses_nested_hold` | `TestMarkerSwapNeverBypassesNestedHold` (descriptor_safety_test.go) |
| `test_copy_pins_destination_identity` | `TestCopyPinsDestinationIdentity` (descriptor_safety_test.go) |
| `test_copy_refuses_symlink_destination_ancestor` | `TestCopyRefusesSymlinkDestinationAncestor` (descriptor_safety_test.go) |
| `test_file_modified_during_hash_fails_closed` | `TestFileModifiedDuringHashFailsClosed` (descriptor_safety_test.go) |
| `test_copy_preserves_marker_age_and_executable_mode` | `TestCopyPreservesMarkerAgeAndExecutableMode` (descriptor_safety_test.go) |
| `test_final_rename_does_not_follow_replaced_parent` | `TestFinalRenameDoesNotFollowReplacedParent` (descriptor_safety_test.go) |
| `test_discovery_never_follows_swapped_child` | `TestDiscoveryNeverFollowsSwappedChild` (descriptor_safety_test.go) |
| `test_remote_move_round_trip_uses_local_fixture_transport` | `TestRemoteMoveRoundTripUsesLocalFixtureTransport` (remote_transfer_test.go) |
| `test_replaced_folder_after_evaluation_is_kept` | `TestReplacedFolderAfterEvaluationIsKept` (descriptor_safety_test.go) |
| `test_resource_fork_keeps_source_during_move` | `TestResourceForkKeepsSourceDuringMove` (descriptor_safety_test.go) |
| `test_marker_parsing_and_defaults` | `TestMarkerParsingAndDefaults` (core_test.go) |
| `test_bad_markers_are_kept` | `TestBadMarkersAreKept` (core_test.go) |
| `test_ttl_and_size_parsing` | `TestTTLAndSizeParsing` (core_test.go) |
| `test_mark_touch_cli_round_trip` | `TestMarkTouchCLIRoundTrip` (cli_test.go) |
| `test_fresh_vs_expired` | `TestFreshVsExpired` (core_test.go) |
| `test_sweep_dry_run_by_default_and_armed_after_grace` | `TestSweepDryRunByDefaultAndArmedAfterGrace` (cli_test.go) |
| `test_sweep_summary_counts_every_kept_folder` | `TestSweepSummaryCountsEveryKeptFolder` (cli_test.go) |
| `test_builtin_deny_list` | `TestBuiltinDenyList` (core_test.go) |
| `test_deny_allows_ordinary_caches` | `TestDenyAllowsOrdinaryCaches` (core_test.go) |
| `test_config_only_adds_to_deny` | `TestConfigOnlyAddsToDeny` (core_test.go) |
| `test_mark_refuses_denied` | `TestMarkRefusesDenied` (cli_test.go) |
| `test_denied_descendants_block` | `TestDeniedDescendantsBlock` (core_test.go) |
| `test_config_floors_hosts_ttls_and_validation` | `TestConfigFloorsHostsTTLsAndValidation` (core_test.go) |
| `test_exclude_list_export` | `TestExcludeListExport` (core_test.go) |
| `test_holds_block_and_release` | `TestHoldsBlockAndRelease` (cli_test.go) |
| `test_live_lease_referencing_folder_holds` | `TestLiveLeaseReferencingFolderHolds` (safety_test.go) |
| `test_lease_for_same_job_holds` | `TestLeaseForSameJobHolds` (safety_test.go) |
| `test_lease_dir_glob` | `TestLeaseDirGlob` (safety_test.go) |
| `test_malformed_lease_fails_closed` | `TestMalformedLeaseFailsClosed` (safety_test.go) |
| `test_running_claim_record_holds` | `TestRunningClaimRecordHolds` (safety_test.go) |
| `test_command_holder_exit_codes` | `TestCommandHolderExitCodes` (safety_test.go) |
| `test_command_holder_gets_marker_fields` | `TestCommandHolderGetsMarkerFields` (safety_test.go) |
| `test_command_holder_timeout_and_missing_fail_closed` | `TestCommandHolderTimeoutAndMissingFailClosed` (safety_test.go) |
| `test_config_dir_placeholder` | `TestConfigDirPlaceholder` (safety_test.go) |
| `test_open_files_block` | `TestOpenFilesBlock` (safety_test.go) |
| `test_job_open_blocks` | `TestJobOpenBlocks` (safety_test.go) |
| `test_job_unknown_or_unconfigured_not_eligible` | `TestJobUnknownOrUnconfiguredNotEligible` (safety_test.go) |
| `test_job_closed_but_session_running_blocks` | `TestJobClosedButSessionRunningBlocks` (safety_test.go) |
| `test_pgrep_miss_is_unknown_not_exited` | `TestPgrepMissIsUnknownNotExited` (safety_test.go) |
| `test_ttl_counts_from_job_close_and_session_exit` | `TestTtlCountsFromJobCloseAndSessionExit` (safety_test.go) |
| `test_mirror_descendant_deny_names_apply` | `TestMirrorDescendantDenyNamesApply` (safety_test.go) |
| `test_dirty_and_unpushed_worktrees_refused` | `TestDirtyAndUnpushedWorktreesRefused` (safety_test.go) |
| `test_mirror_still_checks_nested_repos` | `TestMirrorStillChecksNestedRepos` (safety_test.go) |
| `test_move_verifies_then_deletes` | `TestMoveVerifiesThenDeletes` (removal_test.go) |
| `test_hash_mismatch_keeps_source` | `TestHashMismatchKeepsSource` (removal_test.go) |
| `test_marker_touched_after_evaluation_is_kept` | `TestMarkerTouchedAfterEvaluationIsKept` (removal_test.go) |
| `test_hold_added_during_move_keeps_source` | `TestHoldAddedDuringMoveKeepsSource` (removal_test.go) |
| `test_lease_appearing_during_move_keeps_source` | `TestLeaseAppearingDuringMoveKeepsSource` (removal_test.go) |
| `test_source_modified_during_move_keeps_source` | `TestSourceModifiedDuringMoveKeepsSource` (removal_test.go) |
| `test_hold_and_removal_share_one_lock` | `TestHoldAndRemovalShareOneLock` (removal_test.go) |
| `test_rmtree_does_not_cross_filesystems` | `TestRmtreeDoesNotCrossFilesystems` (removal_test.go) |
| `test_floor_takes_lru_safe_before_ttl` | `TestFloorTakesLRUSafeBeforeTTL` (cli_test.go) |
| `test_scan_does_not_descend_into_marked_or_denied` | `TestScanDoesNotDescendIntoMarkedOrDenied` (core_test.go) |
| `test_symlink_root_and_ancestor_refused_everywhere` | `TestSymlinkRootAndAncestorRefusedEverywhere` (removal_test.go) |
| `test_folder_swapped_for_symlink_before_rename_is_restored` | `TestFolderSwappedForSymlinkBeforeRenameIsRestored` (removal_test.go) |
| `test_glob_deny_paths_apply_to_descendants` | `TestGlobDenyPathsApplyToDescendants` (core_test.go) |
| `test_nested_primary_repo_in_mirror_refused` | `TestNestedPrimaryRepoInMirrorRefused` (safety_test.go) |
| `test_session_grace_unset_keeps_unobservable_session` | `TestSessionGraceUnsetKeepsUnobservableSession` (safety_test.go) |
| `test_session_grace_not_elapsed_keeps` | `TestSessionGraceNotElapsedKeeps` (safety_test.go) |
| `test_session_grace_elapsed_counts_as_gone` | `TestSessionGraceElapsedCountsAsGone` (safety_test.go) |
| `test_missing_close_time_counts_from_first_observation` | `TestMissingCloseTimeCountsFromFirstObservation` (safety_test.go) |
| `test_missing_close_time_ttl_counts_from_first_observation` | `TestMissingCloseTimeTtlCountsFromFirstObservation` (safety_test.go) |
| `test_session_grace_requires_successful_nomatch_probe` | `TestSessionGraceRequiresSuccessfulNomatchProbe` (safety_test.go) |
| `test_unreadable_lease_and_claim_dirs_fail_closed` | `TestUnreadableLeaseAndClaimDirsFailClosed` (safety_test.go) |
| `test_unreadable_dir_inside_lease_glob_fails_closed` | `TestUnreadableDirInsideLeaseGlobFailsClosed` (safety_test.go) |
| `test_session_grace_needs_closed_job_and_ignores_pids_and_live_hits` | `TestSessionGraceNeedsClosedJobAndIgnoresPidsAndLiveHits` (safety_test.go) |
| `test_session_grace_config_parsing` | `TestSessionGraceConfigParsing` (core_test.go) |
| `test_dirty_file_added_after_evaluation_blocks_removal` | `TestDirtyFileAddedAfterEvaluationBlocksRemoval` (removal_test.go) |
| `test_unpushed_commit_after_evaluation_blocks_removal` | `TestUnpushedCommitAfterEvaluationBlocksRemoval` (removal_test.go) |
| `test_nested_repo_dirtied_after_evaluation_blocks_removal` | `TestNestedRepoDirtiedAfterEvaluationBlocksRemoval` (removal_test.go) |
| `test_dirty_file_added_during_move_keeps_source` | `TestDirtyFileAddedDuringMoveKeepsSource` (removal_test.go) |
| `test_job_state_change_after_evaluation_blocks_removal` | `TestJobStateChangeAfterEvaluationBlocksRemoval` (removal_test.go) |
| `test_job_still_closed_removes` | `TestJobStillClosedRemoves` (removal_test.go) |
| `test_job_label_added_during_move_keeps_source` | `TestJobLabelAddedDuringMoveKeepsSource` (removal_test.go) |
| `test_numeric_session_alive_after_evaluation_blocks_removal` | `TestNumericSessionAliveAfterEvaluationBlocksRemoval` (safety_test.go) |
| `test_session_appearing_alive_between_evaluate_and_removal_is_kept` | `TestSessionAppearingAliveBetweenEvaluateAndRemovalIsKept` (safety_test.go) |
| `test_session_probe_failing_at_removal_is_kept` | `TestSessionProbeFailingAtRemovalIsKept` (safety_test.go) |
| `test_session_alive_during_move_keeps_source` | `TestSessionAliveDuringMoveKeepsSource` (safety_test.go) |
| `test_session_still_gone_at_removal_removes` | `TestSessionStillGoneAtRemovalRemoves` (safety_test.go) |
| `test_relative_mark_and_evaluate_apply_absolute_glob_deny` | `TestRelativeMarkAndEvaluateApplyAbsoluteGlobDeny` (core_test.go) |
| `test_relative_registry_entries_are_ignored_not_deleted` | `TestRelativeRegistryEntriesAreIgnoredNotDeleted` (core_test.go) |
| `test_job_reclosed_recently_keeps_ttl_candidate` | `TestJobReclosedRecentlyKeepsTtlCandidate` (removal_test.go) |
| `test_floor_pressure_candidate_ignores_recomputed_clock` | `TestFloorPressureCandidateIgnoresRecomputedClock` (removal_test.go) |
| `test_job_reclosed_during_move_keeps_source` | `TestJobReclosedDuringMoveKeepsSource` (removal_test.go) |
| `test_sweep_ttl_selected_candidate_still_removed` | `TestSweepTtlSelectedCandidateStillRemoved` (removal_test.go) |
| `test_relative_volume_floors_key_is_absolute` | `TestRelativeVolumeFloorsKeyIsAbsolute` (cli_test.go) |
| `test_plan_matches_volume_floor_by_absolute_mount` | `TestPlanMatchesVolumeFloorByAbsoluteMount` (cli_test.go) |
| `test_marker_without_regenerate_is_invalid_and_kept` | `TestMarkerWithoutRegenerateIsInvalidAndKept` (core_test.go) |
| `test_hardlinks_are_counted_once` | `TestHardlinksAreCountedOnce` (safety_test.go) |
| `test_pressure_sweep_stops_when_real_free_space_reaches_target` | `TestPressureSweepStopsWhenRealFreeSpaceReachesTarget` (cli_test.go) |
| `test_pressure_sweep_continues_when_estimate_overstates_reclaimed_space` | `TestPressureSweepContinuesWhenEstimateOverstatesReclaimedSpace` (cli_test.go) |
| `test_worktree_with_ignored_files_needs_ignored_ok` | `TestWorktreeWithIgnoredFilesNeedsIgnoredOk` (safety_test.go) |
| `test_ignored_file_added_before_removal_blocks` | `TestIgnoredFileAddedBeforeRemovalBlocks` (safety_test.go) |
| `test_nested_linked_worktree_ignored_files` | `TestNestedLinkedWorktreeIgnoredFiles` (safety_test.go) |
| `test_ignored_ok_must_be_boolean` | `TestIgnoredOkMustBeBoolean` (core_test.go) |
| `test_jj_secondary_workspace_ignored_files` | `TestJjSecondaryWorkspaceIgnoredFiles` (safety_test.go) |
| `test_data_volume_alias_of_protected_path_is_refused` | `TestDataVolumeAliasOfProtectedPathIsRefused` (aliases_test.go) |
| `test_case_variants_of_protected_paths` | `TestCaseVariantsOfProtectedPaths` (aliases_test.go) |
| `test_unicode_normalisation_variants` | `TestUnicodeNormalisationVariants` (aliases_test.go) |
| `test_photoslibrary_uppercase` | `TestPhotoslibraryUppercase` (aliases_test.go) |
| `test_case_variant_descendant_names_block` | `TestCaseVariantDescendantNamesBlock` (aliases_test.go) |
| `test_case_variant_descendant_glob_and_git_dirs` | `TestCaseVariantDescendantGlobAndGitDirs` (aliases_test.go) |
| `test_identity_catches_other_spellings_of_a_protected_dir` | `TestIdentityCatchesOtherSpellingsOfAProtectedDir` (aliases_test.go) |
| `test_data_prefix_variants_block_combined_glob_bypass` | `TestDataPrefixVariantsBlockCombinedGlobBypass` (aliases_test.go) |
| `test_decomposed_data_prefix_is_canonical` | `TestDecomposedDataPrefixIsCanonical` (aliases_test.go) |
| `test_glob_deny_protects_hardlink_identity` | `TestGlobDenyProtectsHardlinkIdentity` (aliases_test.go) |
| `test_glob_identity_expansion_folds_literal_components` | `TestGlobIdentityExpansionFoldsLiteralComponents` (aliases_test.go) |
| `test_unreadable_deny_glob_fails_closed` | `TestUnreadableDenyGlobFailsClosed` (aliases_test.go) |
| `test_data_prefix_variants_in_deny_patterns_and_walk` | `TestDataPrefixVariantsInDenyPatternsAndWalk` (aliases_test.go) |
| `test_related_paths_fold_normalise_and_strip_prefix` | `TestRelatedPathsFoldNormaliseAndStripPrefix` (aliases_test.go) |
| `test_lease_data_alias_and_case_variant_holds` | `TestLeaseDataAliasAndCaseVariantHolds` (aliases_test.go) |
| `test_discovery_roots_use_canonical_comparisons` | `TestDiscoveryRootsUseCanonicalComparisons` (aliases_test.go) |
| `test_export_broad_roots_use_canonical_comparisons` | `TestExportBroadRootsUseCanonicalComparisons` (aliases_test.go) |
| `test_double_slash_data_prefix_and_component_boundaries` | `TestDoubleSlashDataPrefixAndComponentBoundaries` (aliases_test.go) |
| `test_scan_pruning_folds_paths_and_names` | `TestScanPruningFoldsPathsAndNames` (aliases_test.go) |
| `test_hold_paths_deduplicate_and_release_canonical_alias` | `TestHoldPathsDeduplicateAndReleaseCanonicalAlias` (aliases_test.go) |
| `test_volume_floor_lookup_uses_canonical_path` | `TestVolumeFloorLookupUsesCanonicalPath` (aliases_test.go) |
| `test_glob_ancestor_identity_protects_other_alias` | `TestGlobAncestorIdentityProtectsOtherAlias` (aliases_test.go) |
| `test_missing_glob_is_not_a_global_veto` | `TestMissingGlobIsNotAGlobalVeto` (aliases_test.go) |
| `test_nested_marker_independent_protection` | `TestNestedMarkerIndependentProtection` (safety_test.go) |
| `test_nested_marker_case_variants_protect_ancestor` | `TestNestedMarkerCaseVariantsProtectAncestor` (safety_test.go) |
| `test_expired_nested_marker_can_be_removed_with_ancestor` | `TestExpiredNestedMarkerCanBeRemovedWithAncestor` (safety_test.go) |
| `test_nested_marker_uses_its_own_holder_context` | `TestNestedMarkerUsesItsOwnHolderContext` (safety_test.go) |
| `test_invalid_nested_marker_fails_closed` | `TestInvalidNestedMarkerFailsClosed` (safety_test.go) |
| `test_nested_marker_rechecked_before_ancestor_removal` | `TestNestedMarkerRecheckedBeforeAncestorRemoval` (safety_test.go) |
| `test_outer_ignored_ok_does_not_override_nested_marker` | `TestOuterIgnoredOkDoesNotOverrideNestedMarker` (safety_test.go) |
| `test_nested_marker_final_copy_recheck_keeps_source` | `TestNestedMarkerFinalCopyRecheckKeepsSource` (safety_test.go) |
| `test_nested_marker_own_deny_exact_keeps_ancestor` | `TestNestedMarkerOwnDenyExactKeepsAncestor` (safety_test.go) |
| `test_nested_marker_ignored_ok_independent_and_inherited` | `TestNestedMarkerIgnoredOkIndependentAndInherited` (safety_test.go) |
| `test_remote_transfer_preserves_files_and_links` | `TestRemoteTransferPreservesFilesAndLinks` (remote_transfer_test.go) |
| `test_remote_hash_inventory_preserves_newlines` | `TestRemoteHashInventoryPreservesNewlines` (remote_transfer_test.go) |
| `test_remote_transfer_refuses_existing_destination` | `TestRemoteTransferRefusesExistingDestination` (remote_transfer_test.go) |
| `test_remote_transfer_refuses_symlink_destination_parent` | `TestRemoteTransferRefusesSymlinkDestinationParent` (remote_transfer_test.go) |
| `test_remote_receiver_rejects_traversal_and_link_parent` | `TestRemoteReceiverRejectsTraversalAndLinkParent` (remote_transfer_test.go) |
| `test_remote_hash_refuses_symlink_root` | `TestRemoteHashRefusesSymlinkRoot` (remote_transfer_test.go) |
| `test_remote_receiver_pins_nested_directory_across_members` | `TestRemoteReceiverPinsNestedDirectoryAcrossMembers` (remote_transfer_test.go) |
| `test_remote_transfer_preserves_marker_age` | `TestRemoteTransferPreservesMarkerAge` (remote_transfer_test.go) |
