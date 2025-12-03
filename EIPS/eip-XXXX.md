---
title: Custom sweep threshold for 0x02 validators
description: Allow setting custom balance thresholds for sweep validator withdrawals for 0x02 validators.
author: Dmitry Gusakov (@dgusakov), Dmitry Chernukhin (@madlabman) and Greg Koumoutsos (@gkoumout)
discussions-to: <URL>
status: Draft
type: Standards Track
category: Core
created: 2025-11-25
requires: 7251, 7685
---

## Abstract

This EIP proposes a mechanism to set custom balance thresholds for sweep validator withdrawals for 0x02 validators. This allows validators to specify when they want their rewards to be swept to their withdrawal address, providing greater flexibility and control over their staking rewards.

## Motivation

The current default sweep threshold for 0x02 validators (2,048 ETH) may not meet the needs of all validators. Some validators may prefer to accumulate rewards before sweeping, while others may want to sweep more frequently. By allowing custom sweep thresholds, validators can optimize their reward management according to their individual strategies and preferences. 

Since the introduction of the 0x02 withdrawal credentials type, we have observed a very low rate of validators transitioning to 0x02. One reason is that many validators do not want to wait until they accumulate 2048 ETH in rewards before being able to participate in the automatic sweep of withdrawals. While partial withdrawals were considered a good way to manually withdraw parts of the validator balance, this approach was not widely adopted by staking protocols, node operators, and solo stakers for several reasons. First, it requires a user-initiated transaction to perform a withdrawal. Second, partial withdrawals use the general exit queue, which makes the time between partial withdrawal initiation and fulfillment unpredictable and heavily dependent on the network conditions. This EIP aims to address this issue by allowing validators to set a custom threshold for sweep withdrawals.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174).

### Constants

#### Execution layer

| Name | Value | Comment |
| - | - | - |
| `SET_SWEEP_THRESHOLD_REQUEST_TYPE` | `0x04` | The [EIP-7685](./eip-7685.md) type prefix for set sweep threshold request |
| `SET_SWEEP_THRESHOLD_REQUEST_PREDEPLOY_ADDRESS` | `TBD` | Where to call and store relevant details about set sweep threshold request mechanism |
| `SYSTEM_ADDRESS` | `0xfffffffffffffffffffffffffffffffffffffffe` | Address used to invoke system operation on contract |
| `EXCESS_SET_SWEEP_THRESHOLD_REQUESTS_STORAGE_SLOT` | `0` | |
| `SET_SWEEP_THRESHOLD_REQUEST_COUNT_STORAGE_SLOT` | `1` | |
| `SET_SWEEP_THRESHOLD_REQUEST_QUEUE_HEAD_STORAGE_SLOT` | `2` | Pointer to the head of the set sweep threshold request message queue |
| `SET_SWEEP_THRESHOLD_REQUEST_QUEUE_TAIL_STORAGE_SLOT` | `3` | Pointer to the tail of the set sweep threshold request message queue |
| `SET_SWEEP_THRESHOLD_REQUEST_QUEUE_STORAGE_OFFSET` | `4` | The start memory slot of the in-state set sweep threshold request message queue |
| `MAX_SET_SWEEP_THRESHOLD_REQUESTS_PER_BLOCK` | `2` | Maximum number of set sweep threshold requests that can be dequeued into a block |
| `TARGET_SET_SWEEP_THRESHOLD_REQUESTS_PER_BLOCK` | `1` | |
| `MIN_SET_SWEEP_THRESHOLD_REQUEST_FEE` | `1` | |
| `SET_SWEEP_THRESHOLD_REQUEST_FEE_UPDATE_FRACTION` | `17` | |
| `EXCESS_INHIBITOR` | `2**256-1` | Excess value used to compute the fee before the first system call |

#### Consensus layer

| Name | Value |
| - | - |
| `SWEEP_THRESHOLD_QUOTIENT` | `Gwei(1 * 10**9)` (1 ETH) |

### Execution layer

#### Definitions

* **`FORK_BLOCK`** -- the first block in a blockchain after this EIP has been activated.

#### Set sweep threshold request

The new set sweep threshold request is an [EIP-7685](./eip-7685.md) request with type `0x04` consisting of the following fields:

1. `source_address`: `Bytes20`
2. `validator_pubkey`: `Bytes48`
3. `threshold`: `uint64`

The [EIP-7685](./eip-7685.md) encoding of a set sweep threshold request is computed as follows.
Note that `threshold` is returned by the contract little-endian, and must be encoded as such.

```python
request_type = SET_SWEEP_THRESHOLD_REQUEST_TYPE
request_data = read_set_sweep_threshold_requests()
```

#### Set sweep threshold request contract
The contract has three different code paths, which can be summarized at a high level as follows:

1. Add set sweep threshold request - requires a `70` byte input, concatenated source address, validator public key, and threshold.
2. Fee getter - if the input length is zero, return the current fee required to add a set sweep threshold request.
3. System process - if called by system address, pop off the set sweep threshold requests for the current block from the queue.

##### Add Set Sweep Threshold Request

If call data input to the contract is exactly `70` bytes, perform the following:
1. Ensure enough ETH was sent to cover the current set sweep threshold request fee (`msg.value >= get_fee()`)
2. Increase set sweep threshold request count by `1` for the current block (`increment_count()`)
3. Insert a set sweep threshold request into the queue for the source address, validator public key, and threshold (`insert_set_sweep_threshold_request_into_queue()`)

Specifically, the functionality is defined in pseudocode as the function `add_set_sweep_threshold_request()`:

```python
def add_set_sweep_threshold_request(Bytes48: validator_pubkey, uint64: threshold):
    """
    Add set sweep threshold request adds new request to the set sweep threshold request queue, so long as a sufficient fee is provided.
    """

    # Verify sufficient fee was provided.
    fee = get_fee()
    require(msg.value >= fee, 'Insufficient value for fee')

    # Increment withdrawal request count.
    count = sload(SET_SWEEP_THRESHOLD_REQUEST_PREDEPLOY_ADDRESS, SET_SWEEP_THRESHOLD_REQUEST_COUNT_STORAGE_SLOT)
    sstore(SET_SWEEP_THRESHOLD_REQUEST_PREDEPLOY_ADDRESS, SET_SWEEP_THRESHOLD_REQUEST_COUNT_STORAGE_SLOT, count + 1)

    # Insert into queue.
    queue_tail_index = sload(SET_SWEEP_THRESHOLD_REQUEST_PREDEPLOY_ADDRESS, SET_SWEEP_THRESHOLD_REQUEST_QUEUE_TAIL_STORAGE_SLOT)
    queue_storage_slot = SET_SWEEP_THRESHOLD_REQUEST_QUEUE_STORAGE_OFFSET + queue_tail_index * 3
    sstore(SET_SWEEP_THRESHOLD_REQUEST_PREDEPLOY_ADDRESS, queue_storage_slot, msg.sender)
    sstore(SET_SWEEP_THRESHOLD_REQUEST_PREDEPLOY_ADDRESS, queue_storage_slot + 1, validator_pubkey[0:32])
    sstore(SET_SWEEP_THRESHOLD_REQUEST_PREDEPLOY_ADDRESS, queue_storage_slot + 2, validator_pubkey[32:48] ++ uint64_to_little_endian(threshold))
    sstore(SET_SWEEP_THRESHOLD_REQUEST_PREDEPLOY_ADDRESS, SET_SWEEP_THRESHOLD_REQUEST_QUEUE_TAIL_STORAGE_SLOT, queue_tail_index + 1)
```

###### Fee calculation

The following pseudocode can compute the cost of an individual set sweep threshold request, given a certain number of excess set sweep threshold requests.

```python
def get_fee() -> int:
    excess = sload(SET_SWEEP_THRESHOLD_REQUEST_PREDEPLOY_ADDRESS, EXCESS_SET_SWEEP_THRESHOLD_REQUESTS_STORAGE_SLOT)
    require(excess != EXCESS_INHIBITOR, 'Inhibitor still active')
    return fake_exponential(
        MIN_SET_SWEEP_THRESHOLD_REQUEST_FEE,
        excess,
        SET_SWEEP_THRESHOLD_REQUEST_FEE_UPDATE_FRACTION
    )

def fake_exponential(factor: int, numerator: int, denominator: int) -> int:
    i = 1
    output = 0
    numerator_accum = factor * denominator
    while numerator_accum > 0:
        output += numerator_accum
        numerator_accum = (numerator_accum * numerator) // (denominator * i)
        i += 1
    return output // denominator
```

##### Fee Getter

When the input to the contract is length zero, interpret this as a get request for the current fee, i.e. the contract returns the result of `get_fee()`.

##### System Call

At the end of processing any execution block starting from the `FORK_BLOCK` (i.e. after processing all transactions and after performing the block body set sweep threshold requests validations), call `SET_SWEEP_THRESHOLD_REQUEST_PREDEPLOY_ADDRESS` as `SYSTEM_ADDRESS` with no calldata. The invocation triggers the following:

* The contract's queue is updated based on set sweep threshold requests dequeued and the set sweep threshold requests queue head/tail are reset if the queue has been cleared (`dequeue_set_sweep_threshold_requests()`)
* The contract's excess set sweep threshold requests are updated based on usage in the current block (`update_excess_set_sweep_threshold_requests()`)
* The contract's set sweep threshold requests count is reset to 0 (`reset_set_sweep_threshold_requests_count()`)
Each set sweep threshold request must appear in the EIP-7685 requests list in the exact order returned by `dequeue_set_sweep_threshold_requests()`.

Additionally, the system call and the processing of that block must conform to the following:

* The call has a dedicated gas limit of `30_000_000`.
* Gas consumed by this call does not count against the block’s overall gas usage.
* Both the gas limit assigned to the call and the gas consumed are excluded from any checks against the block’s gas limit.
* The call does not follow [EIP-1559](./eip-1559.md) fee burn semantics — no value should be transferred as part of this call.
* If there is no code at `SET_SWEEP_THRESHOLD_REQUEST_PREDEPLOY_ADDRESS`, the corresponding block **MUST** be marked invalid.
* If the call to the contract fails or returns an error, the block **MUST** be invalidated.

The functionality triggered by the system call is defined in pseudocode as the function `read_set_sweep_threshold_requests()`:

```python
###################
# Public function #
###################

def read_set_sweep_threshold_requests():
    reqs = dequeue_set_sweep_threshold_requests()
    update_excess_set_sweep_threshold_requests()
    reset_set_sweep_threshold_requests_count()
    return ssz.serialize(reqs)

###########
# Helpers #
###########

def little_endian_to_uint64(data: bytes) -> uint64:
    return uint64(int.from_bytes(data, 'little'))

def uint64_to_little_endian(num: uint64) -> bytes:
    return num.to_bytes(8, 'little')

class ValidatorSetSweepThresholdRequest(object):
    source_address: Bytes20
    validator_pubkey: Bytes48
    threshold: uint64

def dequeue_set_sweep_threshold_requests():
    queue_head_index = sload(SET_SWEEP_THRESHOLD_REQUEST_PREDEPLOY_ADDRESS, SET_SWEEP_THRESHOLD_REQUEST_QUEUE_HEAD_STORAGE_SLOT)
    queue_tail_index = sload(SET_SWEEP_THRESHOLD_REQUEST_PREDEPLOY_ADDRESS, SET_SWEEP_THRESHOLD_REQUEST_QUEUE_TAIL_STORAGE_SLOT)
    num_in_queue = queue_tail_index - queue_head_index
    num_dequeued = min(num_in_queue, MAX_SET_SWEEP_THRESHOLD_REQUESTS_PER_BLOCK)

    reqs = []
    for i in range(num_dequeued):
        queue_storage_slot = SET_SWEEP_THRESHOLD_REQUEST_QUEUE_STORAGE_OFFSET + (queue_head_index + i) * 3
        source_address = address(sload(SET_SWEEP_THRESHOLD_REQUEST_PREDEPLOY_ADDRESS, queue_storage_slot)[0:20])
        validator_pubkey = (
            sload(SET_SWEEP_THRESHOLD_REQUEST_PREDEPLOY_ADDRESS, queue_storage_slot + 1)[0:32] + sload(SET_SWEEP_THRESHOLD_REQUEST_PREDEPLOY_ADDRESS, queue_storage_slot + 2)[0:16]
        )
        threshold = little_endian_to_uint64(sload(SET_SWEEP_THRESHOLD_REQUEST_PREDEPLOY_ADDRESS, queue_storage_slot + 2)[16:24])
        req = ValidatorSetSweepThresholdRequest(
            source_address=Bytes20(source_address),
            validator_pubkey=Bytes48(validator_pubkey),
            threshold=uint64(threshold)
        )
        reqs.append(req)

    new_queue_head_index = queue_head_index + num_dequeued
    if new_queue_head_index == queue_tail_index:
        # Queue is empty, reset queue pointers
        sstore(SET_SWEEP_THRESHOLD_REQUEST_PREDEPLOY_ADDRESS, SET_SWEEP_THRESHOLD_REQUEST_QUEUE_HEAD_STORAGE_SLOT, 0)
        sstore(SET_SWEEP_THRESHOLD_REQUEST_PREDEPLOY_ADDRESS, SET_SWEEP_THRESHOLD_REQUEST_QUEUE_TAIL_STORAGE_SLOT, 0)
    else:
        sstore(SET_SWEEP_THRESHOLD_REQUEST_PREDEPLOY_ADDRESS, SET_SWEEP_THRESHOLD_REQUEST_QUEUE_HEAD_STORAGE_SLOT, new_queue_head_index)

    return reqs

def update_excess_set_sweep_threshold_requests():
    previous_excess = sload(SET_SWEEP_THRESHOLD_REQUEST_PREDEPLOY_ADDRESS, EXCESS_SET_SWEEP_THRESHOLD_REQUESTS_STORAGE_SLOT)
    if previous_excess == EXCESS_INHIBITOR:
        previous_excess = 0

    count = sload(SET_SWEEP_THRESHOLD_REQUEST_PREDEPLOY_ADDRESS, SET_SWEEP_THRESHOLD_REQUEST_COUNT_STORAGE_SLOT)
    new_excess = 0
    if previous_excess + count > TARGET_SET_SWEEP_THRESHOLD_REQUESTS_PER_BLOCK:
        new_excess = previous_excess + count - TARGET_SET_SWEEP_THRESHOLD_REQUESTS_PER_BLOCK

    sstore(SET_SWEEP_THRESHOLD_REQUEST_PREDEPLOY_ADDRESS, EXCESS_SET_SWEEP_THRESHOLD_REQUESTS_STORAGE_SLOT, new_excess)

def reset_set_sweep_threshold_requests_count():
    sstore(SET_SWEEP_THRESHOLD_REQUEST_PREDEPLOY_ADDRESS, SET_SWEEP_THRESHOLD_REQUEST_COUNT_STORAGE_SLOT, 0)
```

##### Bytecode

```asm
TBD
```

##### Deployment

The set sweep threshold requests contract is deployed like any other smart contract. A special synthetic address is generated by working backwards from the desired deployment transaction:

```json
TBD
```

```
Sender: TBD
Address: TBD
```

### Consensus layer

The defining feature of this EIP is ***allowing validators to set custom sweep thresholds for their withdrawals when using compounding withdrawal credentials (`0x02, 0x03`)***.

The [Rationale](#rationale) section contains an explanation for this proposed core feature. A sketch of the resulting changes to the consensus layer is included below.

1. Update the `BeaconState` container to include a `validator_sweep_thresholds` mapping.
2. Update the `ExecutionRequests` container to include a list of `SetSweepThresholdRequest`s.
3. Add `SetSweepThresholdRequest` container to represent the set sweep threshold requests dequeued from the execution layer contract.
4. Modify the `is_partially_withdrawable_validator` predicate to take into account the custom sweep threshold.
5. Add `get_effective_sweep_threshold` helper function to compute the effective sweep threshold for a validator.
6. Modify the `get_expected_withdrawals` function to use the custom sweep threshold when determining partial withdrawals.
7. Add `process_set_sweep_threshold_request` function to handle the processing of set sweep threshold requests from the execution layer.
8. Modify the `process_execution_payload` function to include the processing of set sweep threshold requests.
Full consensus layer specification can be found in https://github.com/dgusakov/consensus-specs/pull/1

## Rationale

### Overview
Most of the considerations regarding the messaging format, queue, and rate-limiting are similar to those discussed in [EIP-7002](./eip-7002.md) for partial withdrawal requests, and so we refer the reader to that EIP for more details.

### Custom Sweep Thresholds
The primary motivation for this EIP is to allow validators to set custom sweep thresholds for their withdrawals when using compounding withdrawal credentials (`0x02, 0x03`). This feature provides greater flexibility and control over how and when validators can access their staking rewards.

### `validator_sweep_thresholds` mapping in `BeaconState`
To store the custom sweep thresholds for each validator, we introduce a new mapping in the `BeaconState` container called `validator_sweep_thresholds`. This mapping associates each validator index with its corresponding sweep threshold. This approach was chosen instead of adding a new field to the `Validator` container to avoid modification of the `Validator` container, which had not been changed since phase-0. Modification of the `Validator` container would have required more extensive changes to the consensus layer and potentially affected existing implementations of the applications using this container.

### Immediate requests processing instead of queuing on consensus layer
Unlike partial withdrawal requests, which are queued on the consensus layer, set sweep threshold requests are processed immediately upon being dequeued from the execution layer contract. This design choice simplifies the implementation and reduces the complexity of managing a separate queue on the consensus layer.

### Only allowing threshold to be set above current balance
This design decision is made to prevent usage of the custom sweep threshold mechanism to trigger immediate withdrawals. By enforcing that the threshold must be set above the current balance, we ensure that validators cannot use this feature to bypass the standard withdrawal process. Should a validator wish to set sweep threshold below current balance, they can first withdraw down to the desired level using partial withdrawals, and then set the sweep threshold accordingly.

## Backwards Compatibility

This EIP introduces backwards incompatible changes to the block structure and block validation rule set. But neither of these changes break anything related to current user activity and experience.

## Security Considerations

Most of the security considerations regarding fee overpayment, system call failure, and empty code failure are similar to those discussed in [EIP-7002](./eip-7002.md) for partial withdrawal requests, and so we refer the reader to that EIP for more details.

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).
