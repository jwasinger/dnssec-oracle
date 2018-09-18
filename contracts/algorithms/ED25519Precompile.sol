pragma solidity ^0.4.17;

import "@ensdomains/buffer/contracts/Buffer.sol";
pragma solidity ^0.4.17;

import "@ensdomains/buffer/contracts/Buffer.sol";

library ED25519VerifyPrecompile {
    using Buffer for *;

    /**
    * @dev Computes (base ^ exponent) % modulus over big numbers.
    */
    function modexp(bytes message, bytes publicKey, bytes signature) internal view returns (bool success) {
        uint size = (32 * 3) + base.length + exponent.length + modulus.length;

        Buffer.buffer memory input;
        input.init(size);

        input.appendBytes32(bytes32(message.length));
        input.appendBytes32(bytes32(publicKey.length));
        input.appendBytes32(bytes32(Signature.length));
        input.append(message);
        input.append(publicKey);
        input.append(signature);

        bytes memory output = new bytes(4);

        assembly {
            success := staticcall(gas(), 10, add(mload(input), 32), 128, add(output, 32), 4)
        }

        if (success) {
            if (output != bytes4(hex"ffffffff")) {
                success = false
            }
        }
    }
}
