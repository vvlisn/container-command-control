#!/usr/bin/env bats

@test "accept deployment without args and command when default deny" {
  run kwctl run \
    -r test_data/deployment-no-args.json \
    --settings-json '{"allow_args_and_command": false}' \
    policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request is accepted
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

@test "reject deployment with args when default deny" {
  run kwctl run \
    -r test_data/deployment-with-args.json \
    --settings-json '{"allow_args_and_command": false}' \
    policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
  [ $(expr "$output" : ".*args configuration is not allowed in container 'nginx'.*") -ne 0 ]
}

@test "reject deployment with command and args when default deny" {
  run kwctl run \
    -r test_data/deployment-with-command-args.json \
    --settings-json '{"allow_args_and_command": false}' \
    policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
  [ $(expr "$output" : ".*command configuration is not allowed in container 'nginx'.*") -ne 0 ]
}

@test "accept deployment with args when allowed" {
  run kwctl run \
    -r test_data/deployment-with-args.json \
    --settings-json '{"allow_args_and_command": true}' \
    policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

@test "accept deployment with command and args when allowed" {
  run kwctl run \
    -r test_data/deployment-with-command-args.json \
    --settings-json '{"allow_args_and_command": true}' \
    policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}












