import gleam/bit_array
import gleam/http
import gleam/http/request
import gleam/http/response.{Response}
import gleam/int
import gleam/list
import gleam/option
import gleam/result
import gleam/string
import gleeunit/should
import licence_audit
import licence_audit/archive_download
import licence_audit/cli
import licence_audit/color
import licence_audit/hex
import licence_audit/httpc_adaptive
import licence_audit/network
import licence_audit/notice
import licence_audit/osv
import licence_audit/picker
import licence_audit/progress
import licence_audit/source_archive_test
import licence_audit/test_policy
import licence_audit/update

type State

const indices = [0, 1, 2, 3, 4, 5, 6, 7]

@external(erlang, "network_test_ffi", "with_state")
fn with_state(action: fn(State) -> a) -> a

@external(erlang, "network_test_ffi", "work")
fn work(state: State, index: Int, crash: Bool) -> Int

@external(erlang, "network_test_ffi", "blocked")
fn blocked(state: State, index: Int) -> Int

@external(erlang, "network_test_ffi", "count")
fn count(state: State, key: String) -> Int

@external(erlang, "network_test_ffi", "increment")
fn increment(state: State, key: String) -> Int

@external(erlang, "network_test_ffi", "workers_stopped")
fn workers_stopped(state: State) -> Bool

@external(erlang, "network_test_ffi", "record_worker")
fn record_worker(state: State, index: Int) -> Nil

@external(erlang, "network_test_ffi", "kill_caller")
fn kill_caller(state: State, run: fn() -> Nil) -> Nil

@external(erlang, "network_test_ffi", "with_peer")
fn with_peer(tls: Bool, action: fn(State, String) -> a) -> a

@external(erlang, "network_test_ffi", "assert_drained")
fn assert_drained(state: State) -> Nil

@external(erlang, "network_test_ffi", "now_ms")
fn now_ms() -> Int

@external(erlang, "network_test_ffi", "elapsed_ms")
fn elapsed_ms() -> Int

@external(erlang, "network_test_ffi", "sleep")
fn sleep(wait_ms: Int) -> Nil

@external(erlang, "network_test_ffi", "probe_owner_recovery")
fn probe_owner_recovery() -> Nil

@external(erlang, "network_test_ffi", "cancelled_open_replies")
fn cancelled_open_replies() -> Nil

@external(erlang, "network_test_ffi", "queued_open_deadline")
fn queued_open_deadline() -> Nil

@external(erlang, "network_test_ffi", "preparation_failure")
fn preparation_failure() -> Nil

@external(erlang, "network_test_ffi", "lose_guardian")
fn lose_guardian() -> Nil

@external(erlang, "network_test_ffi", "unconfirmed_open")
fn unconfirmed_open() -> Nil

pub fn ownership_loss_and_unknown_open_never_report_completed_fetch_test() {
  list.each([lose_guardian, unconfirmed_open], fn(interrupt) {
    let outcomes =
      network.fetch(["required-input"], fn(input) { input }, fn(_) {
        interrupt()
      })
    let assert [Error(reason)] = outcomes
    assert string.contains(reason, "Fetch for required-input is incomplete")
    assert string.contains(reason, "teardown proof lost")
  })
}

@external(erlang, "network_test_ffi", "with_project")
fn with_project(archive: BitArray, action: fn(String) -> a) -> a

fn package_index(name: String) -> Int {
  let assert Ok(index) = name |> string.replace("package", "") |> int.parse
  index
}

pub fn real_command_fetch_loops_admit_four_and_reduce_in_input_order_test() {
  let archive = source_archive_test.notice_archive(["MIT"])
  with_project(archive, fn(root) {
    list.each(
      [
        ["report"],
        ["check", test_policy.flag(["MIT"], [])],
        ["notices", "--scope=all"],
        ["sbom"],
        ["sbom", "--reproducible"],
        ["vulns"],
        ["check", "--checks=vulns"],
        ["sbom", "--vulns"],
      ],
      fn(command) {
        with_state(fn(state) {
          let clients =
            licence_audit.Clients(
              fetcher: fn(name) {
                let _ = work(state, package_index(name), False)
                Ok(hex.licences_only(["MIT"]))
              },
              publication_fetcher: fn(_, _) {
                panic as "Hex needs no publication lookup"
              },
              notice_clients: notice.Clients(
                ..notice.default_clients(),
                fetch_hex_tarball: fn(name, _) {
                  let _ = work(state, package_index(name), False)
                  Ok(archive)
                },
                fetch_spdx_index: fn(_) { Ok(["MIT"]) },
                fetch_spdx: fn(_) { Ok(option.Some("MIT licence text")) },
              ),
              osv_batch_fetcher: fn(purls) {
                Ok(
                  list.index_map(purls, fn(purl, index) {
                    osv.BatchEntry(purl, ["OSV-" <> int.to_string(index)])
                  }),
                )
              },
              osv_detail_fetcher: fn(id) {
                let assert Ok(index) =
                  id |> string.replace("OSV-", "") |> int.parse
                let _ = work(state, index, False)
                Ok(osv.Vulnerability(id, [], id, osv.Low, [], []))
              },
            )
          let #(outcome, _) =
            licence_audit.run_configured(
              list.append(command, ["--manifest=" <> root <> "/manifest.toml"]),
              clients,
              progress.capturing(progress.Verbose, "test"),
            )
          should.equal(#(command, outcome.exit_code), #(command, 0))
          should.equal(count(state, "maximum"), 4)
          let positions =
            list.map(indices, fn(index) {
              let name = "package" <> int.to_string(index)
              assert string.contains(outcome.output, name)
              let assert [before, ..] = string.split(outcome.output, name)
              string.length(before)
            })
          should.equal(positions, list.sort(positions, int.compare))
          should.be_true(workers_stopped(state))
        })
      },
    )
    with_state(fn(state) {
      let clients =
        notice.Clients(
          ..notice.default_clients(),
          fetch_hex_tarball: fn(name, _) {
            let _ = work(state, package_index(name), False)
            Ok(archive)
          },
        )
      let #(outcome, _) =
        update.run_with_picker(
          root <> "/manifest.toml",
          root,
          cli.UpdateOptions(
            manifest_path: option.None,
            config_path: option.None,
            verbosity: progress.Verbose,
            color: color.Never,
            no_cache: True,
            cache_dir: option.None,
            allow: option.None,
            deny: option.None,
            dry_run: False,
          ),
          clients,
          fn(_, _, _, _) { Error(picker.Cancelled) },
          progress.capturing(progress.Verbose, "update"),
        )
      should.equal(outcome.exit_code, 130)
      should.equal(count(state, "maximum"), 4)
      should.be_true(workers_stopped(state))
    })
  })
}

pub fn killed_probe_owner_does_not_poison_other_hosts_test() {
  reset()
  probe_owner_recovery()
  reset()
}

pub fn timed_out_open_cannot_leave_replies_or_accept_a_late_result_test() {
  cancelled_open_replies()
  queued_open_deadline()
}

pub fn ca_preparation_failure_keeps_the_command_guardian_usable_test() {
  preparation_failure()
}

type Interruption {
  Worker
  Helper
  Sender
}

@external(erlang, "network_test_ffi", "interrupt_http")
fn interrupt_http(state: State, interruption: Interruption) -> Nil

@external(erlang, "httpc_adaptive_ffi", "select_ipv4")
fn select_ipv4() -> Nil

@external(erlang, "httpc_adaptive_test_ffi", "reset")
fn reset() -> Nil

@external(erlang, "httpc_adaptive_test_ffi", "with_retry_response")
fn with_retry_response(bytes: String, client: fn(String) -> a) -> #(a, Int)

@external(erlang, "httpc_adaptive_test_ffi", "with_backlog_response")
fn with_backlog_response(bytes: BitArray, client: fn(String) -> a) -> #(a, Int)

@external(erlang, "archive_download_test_ffi", "with_untrusted_tls")
fn with_untrusted_tls(client: fn(String) -> a) -> a

pub fn four_workers_preserve_result_and_deferred_event_order_test() {
  with_state(fn(state) {
    let reporter = progress.capturing(progress.Verbose, "report")
    let outcomes =
      network.fetch(indices, int.to_string, fn(index) {
        let value = work(state, index, False)
        let captured =
          progress.fork(reporter)
          |> progress.detail("fetched " <> int.to_string(index))
          |> progress.defer_warn("warning " <> int.to_string(index))
        #(value, captured)
      })
    let values = list.filter_map(outcomes, result.map(_, fn(value) { value.0 }))
    should.equal(values, indices)
    should.equal(count(state, "maximum"), 4)
    let reporter =
      list.fold(outcomes, reporter, fn(reporter, outcome) {
        let assert Ok(#(_, captured)) = outcome
        progress.merge(reporter, captured)
      })
    should.equal(
      progress.events(reporter) |> list.map(fn(event) { event.message }),
      indices
        |> list.flat_map(fn(index) {
          [
            "fetched " <> int.to_string(index),
            "warning " <> int.to_string(index),
          ]
        }),
    )
    should.equal(
      list.reverse(reporter.deferred)
        |> list.map(fn(event) { event.message }),
      list.map(indices, fn(index) { "warning " <> int.to_string(index) }),
    )
    should.be_true(workers_stopped(state))
  })
}

pub fn worker_crash_and_deadline_keep_input_cardinality_and_correlation_test() {
  with_state(fn(state) {
    let outcomes =
      network.fetch(indices, int.to_string, fn(index) {
        work(state, index, index == 2)
      })
    should.equal(list.length(outcomes), 8)
    let assert [Ok(0), Ok(1), Error(reason), Ok(3), Ok(4), Ok(5), Ok(6), Ok(7)] =
      outcomes
    assert string.contains(reason, "Fetch for 2 is incomplete")
    should.be_true(workers_stopped(state))
  })
  with_state(fn(state) {
    let outcomes =
      network.fetch_with_deadline(
        indices,
        int.to_string,
        blocked(state, _),
        100,
      )
    should.equal(list.length(outcomes), 8)
    list.each(list.zip(indices, outcomes), fn(pair) {
      let assert Error(reason) = pair.1
      assert string.contains(reason, "Fetch for " <> int.to_string(pair.0))
    })
    should.be_true(workers_stopped(state))
  })
}

pub fn caller_death_joins_workers_test() {
  with_state(fn(state) {
    kill_caller(state, fn() {
      let _ = network.fetch(indices, int.to_string, blocked(state, _))
      Nil
    })
    should.be_true(workers_stopped(state))
  })
}

pub fn typed_probe_errors_are_shared_without_fallback_or_real_requests_test() {
  reset()
  with_state(fn(state) {
    network.with_command(fn() {
      let assert Ok(req) = request.to("https://hex.invalid/package")
      let outcomes =
        network.fetch(indices, int.to_string, fn(_) {
          httpc_adaptive.dispatch_managed_bits_with(
            request.map(req, bit_array.from_string),
            500,
            fn(sent, _, _) {
              should.equal(sent.method, http.Head)
              let _ = increment(state, "probe")
              Error(httpc_adaptive.TlsFailure("unknown_ca"))
            },
          )
        })
      should.equal(
        outcomes,
        list.repeat(Ok(Error(httpc_adaptive.TlsFailure("unknown_ca"))), 8),
      )
      should.equal(count(state, "probe"), 1)
      should.equal(httpc_adaptive.take_warning(), option.None)
    })
  })
  reset()
}

pub fn one_shared_probe_selects_ipv4_for_all_workers_and_warns_once_test() {
  reset()
  with_state(fn(state) {
    network.with_command(fn() {
      let assert Ok(req) = request.to("https://hex.invalid/package")
      let req = request.map(req, bit_array.from_string)
      let outcomes =
        network.fetch(indices, int.to_string, fn(_) {
          httpc_adaptive.dispatch_managed_bits_with(
            req,
            500,
            fn(sent, timeout, family) {
              case sent.method {
                http.Head -> {
                  should.equal(timeout, 1000)
                  should.equal(family, httpc_adaptive.Ipv6)
                  let _ = increment(state, "probe")
                  sleep(20)
                  Error(httpc_adaptive.ResponseTimeout)
                }
                _ -> {
                  should.equal(family, httpc_adaptive.Ipv4)
                  let _ = increment(state, "requests")
                  Ok(Response(200, [], <<>>))
                }
              }
            },
          )
        })
      should.equal(outcomes, list.repeat(Ok(Ok(Response(200, [], <<>>))), 8))
      should.equal(count(state, "probe"), 1)
      should.equal(count(state, "requests"), 8)
      let assert option.Some(_) = httpc_adaptive.take_warning()
      should.equal(httpc_adaptive.take_warning(), option.None)
    })
  })
  reset()
}

pub fn shared_cutoff_counts_logical_operations_and_keeps_hosts_isolated_test() {
  reset()
  with_state(fn(state) {
    network.with_command(fn() {
      let assert Ok(req) = request.to("https://hex.invalid/package")
      let outcomes =
        network.fetch([0, 1, 2], int.to_string, fn(_) {
          httpc_adaptive.dispatch_retry_with(
            req,
            2,
            fn(_) {
              let _ = increment(state, "attempts")
              Error(httpc_adaptive.ResponseTimeout)
            },
            now_ms,
            elapsed_ms,
            fn(_) { Nil },
          )
        })
      should.equal(
        outcomes,
        list.repeat(Ok(Error(httpc_adaptive.ResponseTimeout)), 3),
      )
      should.equal(count(state, "attempts"), 9)
      let stopped =
        httpc_adaptive.dispatch_retry_with(
          req,
          2,
          fn(_) { panic as "stopped host must not issue HTTP" },
          now_ms,
          elapsed_ms,
          sleep,
        )
      should.equal(
        stopped,
        Error(httpc_adaptive.HostUnavailable("hex.invalid")),
      )
      let other = request.set_host(req, "osv.invalid")
      should.equal(
        httpc_adaptive.dispatch_retry_with(
          other,
          0,
          fn(_) { Ok(Response(200, [], "")) },
          now_ms,
          elapsed_ms,
          sleep,
        ),
        Ok(Response(200, [], "")),
      )
    })
  })
  reset()
}

pub fn archive_exhaustion_stops_metadata_on_the_same_host_test() {
  reset()
  select_ipv4()
  network.with_command(fn() {
    let assert Ok(req) = request.to("https://hex.invalid/archive")
    let req = request.map(req, bit_array.from_string)
    let outcomes =
      network.fetch([0, 1, 2], int.to_string, fn(_) {
        archive_download.fetch_with(req, 500, 1024, fn(_, _, _, _) {
          Error(archive_download.Timeout)
        })
      })
    should.equal(outcomes, list.repeat(Ok(Error(archive_download.Timeout)), 3))
    should.equal(
      httpc_adaptive.dispatch_retry_with(
        req,
        0,
        fn(_) { panic as "archives exhausted this host" },
        now_ms,
        elapsed_ms,
        sleep,
      ),
      Error(httpc_adaptive.HostUnavailable("hex.invalid")),
    )
    let other = request.set_host(req, "osv.invalid")
    should.equal(
      archive_download.fetch_with(other, 500, 1024, fn(_, _, _, _) {
        Ok(Response(200, [], <<>>))
      }),
      Ok(<<>>),
    )
  })
  reset()
}

pub fn rate_limit_deadlines_apply_to_new_workers_without_blocking_other_hosts_test() {
  network.with_command(fn() {
    let assert Ok(req) = request.to("https://hex.invalid/package")
    let started = elapsed_ms()
    let _ =
      httpc_adaptive.dispatch_retry_with(
        req,
        0,
        fn(_) { Ok(Response(429, [#("retry-after", "1")], "")) },
        now_ms,
        elapsed_ms,
        sleep,
      )
    let outcomes =
      network.fetch([0, 1, 2, 3], int.to_string, fn(_) {
        httpc_adaptive.dispatch_retry_with(
          req,
          0,
          fn(_) {
            assert elapsed_ms() - started >= 1000
            Ok(Response(200, [], ""))
          },
          now_ms,
          elapsed_ms,
          sleep,
        )
      })
    should.equal(outcomes, list.repeat(Ok(Ok(Response(200, [], ""))), 4))
    let _ =
      httpc_adaptive.dispatch_retry_with(
        req,
        0,
        fn(_) { Ok(Response(429, [#("retry-after", "31")], "")) },
        now_ms,
        elapsed_ms,
        sleep,
      )
    let outcome =
      httpc_adaptive.dispatch_retry_with(
        req,
        0,
        fn(_) { panic as "deadline exceeds wait budget" },
        now_ms,
        elapsed_ms,
        sleep,
      )
    let assert Error(httpc_adaptive.RetryWaitExceeded(wait, 30_000)) = outcome
    assert wait > 30_000
    let other = request.set_host(req, "osv.invalid")
    should.equal(
      httpc_adaptive.dispatch_retry_with(
        other,
        0,
        fn(_) { Ok(Response(200, [], "")) },
        now_ms,
        elapsed_ms,
        sleep,
      ),
      Ok(Response(200, [], "")),
    )
  })
}

pub fn real_metadata_archive_and_tls_setup_cancellation_drains_http_test() {
  list.each([False, True], fn(tls) {
    list.each([False, True], fn(archive) {
      with_peer(tls, fn(state, url) {
        let assert Ok(req) = request.to(url)
        let outcomes =
          network.fetch_with_deadline(
            indices,
            int.to_string,
            fn(index) {
              record_worker(state, index)
              case archive {
                True ->
                  archive_download.fetch_with_limit(
                    request.map(req, bit_array.from_string),
                    5000,
                    1024,
                  )
                  |> result.replace(Nil)
                  |> result.replace_error(Nil)
                False ->
                  httpc_adaptive.dispatch(req, timeout_ms: 5000)
                  |> result.replace(Nil)
                  |> result.replace_error(Nil)
              }
            },
            1000,
          )
        should.equal(list.length(outcomes), 8)
        list.each(outcomes, fn(outcome) {
          should.be_true(result.is_error(outcome))
        })
        should.equal(count(state, "calls"), 4)
        assert_drained(state)
      })
    })
  })
}

pub fn real_http_caller_death_drains_metadata_and_archive_helpers_test() {
  list.each([False, True], fn(tls) {
    list.each([False, True], fn(archive) {
      with_peer(tls, fn(state, url) {
        let assert Ok(req) = request.to(url)
        kill_caller(state, fn() {
          let _ =
            network.fetch(indices, int.to_string, fn(index) {
              record_worker(state, index)
              case archive {
                True ->
                  archive_download.fetch_with_limit(
                    request.map(req, bit_array.from_string),
                    5000,
                    1024,
                  )
                  |> result.replace(Nil)
                  |> result.replace_error(Nil)
                False ->
                  httpc_adaptive.dispatch(req, timeout_ms: 5000)
                  |> result.replace(Nil)
                  |> result.replace_error(Nil)
              }
            })
          Nil
        })
        assert_drained(state)
      })
    })
  })
}

pub fn real_http_worker_helper_and_sender_death_leave_no_late_work_test() {
  list.each([False, True], fn(tls) {
    list.each([Worker, Helper, Sender], fn(interruption) {
      list.each([False, True], fn(archive) {
        with_peer(tls, fn(state, url) {
          let assert Ok(req) = request.to(url)
          interrupt_http(state, interruption)
          let outcomes =
            network.fetch(indices, int.to_string, fn(index) {
              record_worker(state, index)
              case archive {
                True ->
                  archive_download.fetch_with_limit(
                    request.map(req, bit_array.from_string),
                    1000,
                    1024,
                  )
                  |> result.replace(Nil)
                  |> result.map_error(string.inspect)
                False ->
                  httpc_adaptive.dispatch(req, timeout_ms: 1000)
                  |> result.replace(Nil)
                  |> result.map_error(string.inspect)
              }
            })
          should.equal(list.length(outcomes), 8)
          list.each(outcomes, fn(outcome) {
            case outcome {
              Error(reason) -> {
                assert string.contains(reason, "incomplete")
              }
              Ok(fetched) -> should.be_true(result.is_error(fetched))
            }
          })
          assert list.any(outcomes, result.is_error)
          assert_drained(state)
        })
      })
    })
  })
}

pub fn real_plain_metadata_retains_body_status_redirect_and_one_attempt_test() {
  list.each(
    [
      #("503 Unavailable", "Retry-After: 1\r\n"),
      #("302 Found", "Location: /must-not-follow\r\n"),
    ],
    fn(sample) {
      let #(outcomes, attempts) =
        with_retry_response(
          "HTTP/1.1 "
            <> sample.0
            <> "\r\n"
            <> sample.1
            <> "Content-Length: 4\r\n\r\noops",
          fn(url) {
            let assert Ok(req) = request.to(url)
            let outcomes =
              network.fetch([url], fn(url) { url }, fn(_) {
                httpc_adaptive.dispatch(req, timeout_ms: 500)
              })
            sleep(1200)
            outcomes
          },
        )
      let assert [Ok(Ok(response))] = outcomes
      should.equal(response.body, "oops")
      should.equal(response.status, case sample.0 {
        "503 Unavailable" -> 503
        _ -> 302
      })
      should.equal(attempts, 1)
    },
  )
}

pub fn real_plain_metadata_timeout_and_tls_validation_stay_typed_test() {
  with_peer(False, fn(state, url) {
    let assert Ok(req) = request.to(url)
    let started = elapsed_ms()
    let outcomes =
      network.fetch([0], int.to_string, fn(index) {
        record_worker(state, index)
        httpc_adaptive.dispatch(req, timeout_ms: 80)
      })
    should.equal(outcomes, [Ok(Error(httpc_adaptive.ResponseTimeout))])
    assert elapsed_ms() - started < 500
    assert_drained(state)
  })
  with_untrusted_tls(fn(url) {
    let assert Ok(req) = request.to(url)
    let outcomes =
      network.fetch([url], fn(url) { url }, fn(_) {
        httpc_adaptive.dispatch(req, timeout_ms: 1000)
      })
    let assert [Ok(Error(httpc_adaptive.TlsFailure(_)))] = outcomes
  })
}

pub fn scalar_command_metadata_and_archive_timeout_join_tls_and_tcp_test() {
  list.each([False, True], fn(tls) {
    list.each([False, True], fn(archive) {
      with_peer(tls, fn(state, url) {
        let assert Ok(req) = request.to(url)
        network.with_command(fn() {
          case archive {
            True ->
              should.equal(
                archive_download.fetch_with_limit(
                  request.map(req, bit_array.from_string),
                  100,
                  1024,
                ),
                Error(archive_download.Timeout),
              )
            False ->
              should.equal(
                httpc_adaptive.dispatch(req, timeout_ms: 100),
                Error(httpc_adaptive.ResponseTimeout),
              )
          }
        })
        assert_drained(state)
      })
    })
  })
}

pub fn archive_queued_response_after_deadline_cannot_succeed_test() {
  let #(outcome, attempts) =
    with_backlog_response(
      <<
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok":utf8,
      >>,
      fn(url) {
        let assert Ok(req) = request.to(url)
        network.with_command(fn() {
          archive_download.fetch_with_limit(
            request.map(req, bit_array.from_string),
            50,
            1024,
          )
        })
      },
    )
  should.equal(outcome, Error(archive_download.Timeout))
  should.equal(attempts, 1)
}

pub fn advisory_worker_crash_is_exit_two_for_report_gate_and_sbom_test() {
  let clients =
    licence_audit.Clients(
      ..licence_audit.default_clients(),
      fetcher: fn(_) { Ok(hex.licences_only(["Apache-2.0"])) },
      publication_fetcher: fn(_, _) { Ok(hex.Unpublished) },
      osv_batch_fetcher: fn(purls) {
        Ok(list.map(purls, fn(purl) { osv.BatchEntry(purl, ["OSV-crash"]) }))
      },
      osv_detail_fetcher: fn(_) { panic as "advisory worker crashed" },
    )
  list.each(
    [
      ["vulns"],
      ["check", "--checks=vulns"],
      ["sbom", "--vulns"],
    ],
    fn(command) {
      let #(outcome, events) =
        licence_audit.run_configured(
          list.append(command, [
            "--manifest=test/fixtures/manifest_github_git.toml",
            case command {
              ["sbom", ..] -> "--no-cache"
              _ -> "--ignore-config"
            },
          ]),
          clients,
          progress.capturing(progress.Verbose, "test"),
        )
      should.equal(outcome.exit_code, 2)
      should.equal(
        #(
          command,
          string.contains(outcome.output, "incomplete")
            || list.any(events, fn(event) {
            string.contains(event.message, "incomplete")
          }),
        ),
        #(command, True),
      )
    },
  )
}

pub fn required_and_optional_metadata_worker_crashes_exit_two_test() {
  let clients =
    licence_audit.Clients(
      ..licence_audit.default_clients(),
      fetcher: fn(_) { panic as "metadata worker crashed" },
      publication_fetcher: fn(_, _) { Ok(hex.Unpublished) },
      notice_clients: notice.Clients(
        ..source_archive_test.metadata_clients(fn(_) {
          panic as "locked archive worker crashed"
        }),
        fetch_git_archive: fn(_, _) { panic as "git archive worker crashed" },
      ),
    )
  list.each(
    [
      ["report"],
      ["check", test_policy.flag(["Apache-2.0"], [])],
      ["notices", "--scope=all"],
      ["sbom"],
      ["sbom", "--reproducible"],
    ],
    fn(command) {
      let #(outcome, events) =
        licence_audit.run_configured(
          list.append(command, [
            "--manifest=test/fixtures/manifest_github_git.toml",
            case command {
              ["check", ..] | ["sbom", ..] -> "--no-cache"
              _ -> "--ignore-config"
            },
          ]),
          clients,
          progress.capturing(progress.Verbose, "test"),
        )
      should.equal(outcome.exit_code, 2)
      should.equal(
        #(
          command,
          string.contains(outcome.output, "incomplete")
            || list.any(events, fn(event) {
            string.contains(event.message, "incomplete")
          }),
        ),
        #(command, True),
      )
    },
  )
  let #(outcome, reporter) =
    update.run_with_picker(
      "test/fixtures/manifest_github_git.toml",
      "test/fixtures",
      cli.UpdateOptions(
        manifest_path: option.None,
        config_path: option.None,
        verbosity: progress.Verbose,
        color: color.Never,
        no_cache: True,
        cache_dir: option.None,
        allow: option.None,
        deny: option.None,
        dry_run: False,
      ),
      clients.notice_clients,
      fn(_, _, _, _) { panic as "incomplete discovery must not open picker" },
      progress.capturing(progress.Verbose, "update"),
    )
  should.equal(outcome.exit_code, 2)
  assert list.any(progress.events(reporter), fn(event) {
    string.contains(event.message, "incomplete")
  })
}
