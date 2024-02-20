// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import "https://github.com/wormhole-foundation/wormhole/blob/main/ethereum/contracts/interfaces/IWormhole.sol";

contract SimpleGeneralMessage {
    mapping(address => string) public lastMessage;

    IWormhole immutable core_bridge;

    // Note that this is a bytes32. Addresses in Moonbeam are actually bytes24, as wormhole accepts messages from
    // multiple types of protocols, not just EVMs
    mapping(bytes32 => mapping(uint16 => bool)) public myTrustedContracts;
    mapping(bytes32 => bool) public processedMessages;
    uint16 immutable chainId;
    uint16 nonce = 0;

    // https://book.wormhole.com/reference/contracts.html
    constructor(uint16 _chainId, address wormhole_core_bridge_address) {
        chainId = _chainId;
        core_bridge = IWormhole(wormhole_core_bridge_address);
    }

    // Public facing function to send a message across chains
    function sendMessage(
        string memory message,
        address destAddress,
        uint16 destChainId
    ) external payable {
        // Wormhole recommends that message-publishing functions should return their sequence value
        _sendMessageToRecipient(destAddress, destChainId, message, nonce);
        nonce++;
    }

    // This function defines a super simple Wormhole 'module'.
    // A module is just a piece of code which knows how to emit a composable message
    // which can be utilized by other contracts.
    function _sendMessageToRecipient(
        address recipient,
        uint16 _chainId,
        string memory message,
        uint32 _nonce
    ) private returns (uint64) {
        bytes memory payload = abi.encode(
            recipient,
            _chainId,
            msg.sender,
            message
        );

        // Nonce is passed though to the core bridge.
        // This allows other contracts to utilize it for batching or processing.

        // 1 is the consistency level, this message will be emitted after only 1 block
        uint64 sequence = core_bridge.publishMessage(_nonce, payload, 1);

        // The sequence is passed back to the caller, which can be useful relay information.
        // Relaying is not done here, because it would 'lock' others into the same relay mechanism.
        return sequence;
    }

    // TODO: A production app would add onlyOwner security, but this is for testing.
    function addTrustedAddress(bytes32 sender, uint16 _chainId) external {
        myTrustedContracts[sender][_chainId] = true;
    }

    // Verification accepts a single VAA, and is publicly callable.
    function processMyMessage(bytes memory VAA) public {
        // This call accepts single VAAs and headless VAAs
        (IWormhole.VM memory vm, bool valid, string memory reason) = core_bridge
            .parseAndVerifyVM(VAA);

        // Ensure core contract verifies the VAA
        require(valid, reason);

        // Ensure the emitterAddress of this VAA is a trusted address
        require(
            myTrustedContracts[vm.emitterAddress][vm.emitterChainId],
            "Invalid emitter address!"
        );

        // Check that the VAA hasn't already been processed (replay protection)
        require(!processedMessages[vm.hash], "Message already processed");

        // Parse intended data
        // You could attempt to parse the sender from the bytes32, but that's hard, hence why address was included in the payload
        (
            address intendedRecipient,
            uint16 _chainId,
            address sender,
            string memory message
        ) = abi.decode(vm.payload, (address, uint16, address, string));

        // Check that the contract which is processing this VAA is the intendedRecipient
        // If the two aren't equal, this VAA may have bypassed its intended entrypoint.
        // This exploit is referred to as 'scooping'.
        require(
            intendedRecipient == address(this),
            "Not the intended receipient!"
        );

        // Check that the contract that is processing this VAA is the intended chain.
        // By default, a message is accessible by all chains, so we have to define a destination chain & check for it.
        require(_chainId == chainId, "Not the intended chain!");

        // Add the VAA to processed messages so it can't be replayed
        processedMessages[vm.hash] = true;

        // The message content can now be trusted, slap into messages
        lastMessage[sender] = message;
    }
}
