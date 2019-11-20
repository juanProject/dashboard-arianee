// File: @0xcert/ethereum-utils-contracts/src/contracts/math/safe-math.sol

pragma solidity 0.5.6;

/**
 * @dev Math operations with safety checks that throw on error. This contract is based on the
 * source code at:
 * https://github.com/OpenZeppelin/openzeppelin-solidity/blob/master/contracts/math/SafeMath.sol.
 */
library SafeMath
{

  /**
   * @dev Error constants.
   */
  string constant OVERFLOW = "008001";
  string constant SUBTRAHEND_GREATER_THEN_MINUEND = "008002";
  string constant DIVISION_BY_ZERO = "008003";

  /**
   * @dev Multiplies two numbers, reverts on overflow.
   * @param _factor1 Factor number.
   * @param _factor2 Factor number.
   * @return The product of the two factors.
   */
  function mul(
    uint256 _factor1,
    uint256 _factor2
  )
    internal
    pure
    returns (uint256 product)
  {
    // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
    // benefit is lost if 'b' is also tested.
    // See: https://github.com/OpenZeppelin/openzeppelin-solidity/pull/522
    if (_factor1 == 0)
    {
      return 0;
    }

    product = _factor1 * _factor2;
    require(product / _factor1 == _factor2, OVERFLOW);
  }

  /**
   * @dev Integer division of two numbers, truncating the quotient, reverts on division by zero.
   * @param _dividend Dividend number.
   * @param _divisor Divisor number.
   * @return The quotient.
   */
  function div(
    uint256 _dividend,
    uint256 _divisor
  )
    internal
    pure
    returns (uint256 quotient)
  {
    // Solidity automatically asserts when dividing by 0, using all gas.
    require(_divisor > 0, DIVISION_BY_ZERO);
    quotient = _dividend / _divisor;
    // assert(_dividend == _divisor * quotient + _dividend % _divisor); // There is no case in which this doesn't hold.
  }

  /**
   * @dev Substracts two numbers, throws on overflow (i.e. if subtrahend is greater than minuend).
   * @param _minuend Minuend number.
   * @param _subtrahend Subtrahend number.
   * @return Difference.
   */
  function sub(
    uint256 _minuend,
    uint256 _subtrahend
  )
    internal
    pure
    returns (uint256 difference)
  {
    require(_subtrahend <= _minuend, SUBTRAHEND_GREATER_THEN_MINUEND);
    difference = _minuend - _subtrahend;
  }

  /**
   * @dev Adds two numbers, reverts on overflow.
   * @param _addend1 Number.
   * @param _addend2 Number.
   * @return Sum.
   */
  function add(
    uint256 _addend1,
    uint256 _addend2
  )
    internal
    pure
    returns (uint256 sum)
  {
    sum = _addend1 + _addend2;
    require(sum >= _addend1, OVERFLOW);
  }

  /**
    * @dev Divides two numbers and returns the remainder (unsigned integer modulo), reverts when
    * dividing by zero.
    * @param _dividend Number.
    * @param _divisor Number.
    * @return Remainder.
    */
  function mod(
    uint256 _dividend,
    uint256 _divisor
  )
    internal
    pure
    returns (uint256 remainder)
  {
    require(_divisor != 0, DIVISION_BY_ZERO);
    remainder = _dividend % _divisor;
  }

}

// File: @0xcert/ethereum-utils-contracts/src/contracts/permission/abilitable.sol

pragma solidity 0.5.6;


/**
 * @title Contract for setting abilities.
 * @dev For optimization purposes the abilities are represented as a bitfield. Maximum number of
 * abilities is therefore 256. This is an example(for simplicity is made for max 8 abilities) of how
 * this works.
 * 00000001 Ability A - number representation 1
 * 00000010 Ability B - number representation 2
 * 00000100 Ability C - number representation 4
 * 00001000 Ability D - number representation 8
 * 00010000 Ability E - number representation 16
 * etc ...
 * To grant abilities B and C, we would need a bitfield of 00000110 which is represented by number
 * 6, in other words, the sum of abilities B and C. The same concept works for revoking abilities
 * and checking if someone has multiple abilities.
 */
contract Abilitable
{
  using SafeMath for uint;

  /**
   * @dev Error constants.
   */
  string constant NOT_AUTHORIZED = "017001";
  string constant CANNOT_REVOKE_OWN_SUPER_ABILITY = "017002";
  string constant INVALID_INPUT = "017003";

  /**
   * @dev Ability 1 (00000001) is a reserved ability called super ability. It is an
   * ability to grant or revoke abilities of other accounts. Other abilities are determined by the
   * implementing contract.
   */
  uint8 constant SUPER_ABILITY = 1;

  /**
   * @dev Maps address to ability ids.
   */
  mapping(address => uint256) public addressToAbility;

  /**
   * @dev Emits when an address is granted an ability.
   * @param _target Address to which we are granting abilities.
   * @param _abilities Number representing bitfield of abilities we are granting.
   */
  event GrantAbilities(
    address indexed _target,
    uint256 indexed _abilities
  );

  /**
   * @dev Emits when an address gets an ability revoked.
   * @param _target Address of which we are revoking an ability.
   * @param _abilities Number representing bitfield of abilities we are revoking.
   */
  event RevokeAbilities(
    address indexed _target,
    uint256 indexed _abilities
  );

  /**
   * @dev Guarantees that msg.sender has certain abilities.
   */
  modifier hasAbilities(
    uint256 _abilities
  )
  {
    require(_abilities > 0, INVALID_INPUT);
    require(
      addressToAbility[msg.sender] & _abilities == _abilities,
      NOT_AUTHORIZED
    );
    _;
  }

  /**
   * @dev Contract constructor.
   * Sets SUPER_ABILITY ability to the sender account.
   */
  constructor()
    public
  {
    addressToAbility[msg.sender] = SUPER_ABILITY;
    emit GrantAbilities(msg.sender, SUPER_ABILITY);
  }

  /**
   * @dev Grants specific abilities to specified address.
   * @param _target Address to grant abilities to.
   * @param _abilities Number representing bitfield of abilities we are granting.
   */
  function grantAbilities(
    address _target,
    uint256 _abilities
  )
    external
    hasAbilities(SUPER_ABILITY)
  {
    addressToAbility[_target] |= _abilities;
    emit GrantAbilities(_target, _abilities);
  }

  /**
   * @dev Unassigns specific abilities from specified address.
   * @param _target Address of which we revoke abilites.
   * @param _abilities Number representing bitfield of abilities we are revoking.
   * @param _allowSuperRevoke Additional check that prevents you from removing your own super
   * ability by mistake.
   */
  function revokeAbilities(
    address _target,
    uint256 _abilities,
    bool _allowSuperRevoke
  )
    external
    hasAbilities(SUPER_ABILITY)
  {
    if (!_allowSuperRevoke && msg.sender == _target)
    {
      require((_abilities & 1) == 0, CANNOT_REVOKE_OWN_SUPER_ABILITY);
    }
    addressToAbility[_target] &= ~_abilities;
    emit RevokeAbilities(_target, _abilities);
  }

  /**
   * @dev Check if an address has a specific ability. Throws if checking for 0.
   * @param _target Address for which we want to check if it has a specific abilities.
   * @param _abilities Number representing bitfield of abilities we are checking.
   */
  function isAble(
    address _target,
    uint256 _abilities
  )
    external
    view
    returns (bool)
  {
    require(_abilities > 0, INVALID_INPUT);
    return (addressToAbility[_target] & _abilities) == _abilities;
  }

}

// File: @0xcert/ethereum-utils-contracts/src/contracts/permission/ownable.sol

pragma solidity 0.5.6;

/**
 * @dev The contract has an owner address, and provides basic authorization control whitch
 * simplifies the implementation of user permissions. This contract is based on the source code at:
 * https://github.com/OpenZeppelin/openzeppelin-solidity/blob/master/contracts/ownership/Ownable.sol
 */
contract Ownable
{

  /**
   * @dev Error constants.
   */
  string constant NOT_OWNER = "018001";
  string constant ZERO_ADDRESS = "018002";

  /**
   * @dev Address of the owner.
   */
  address public owner;

  /**
   * @dev An event which is triggered when the owner is changed.
   * @param previousOwner The address of the previous owner.
   * @param newOwner The address of the new owner.
   */
  event OwnershipTransferred(
    address indexed previousOwner,
    address indexed newOwner
  );

  /**
   * @dev The constructor sets the original `owner` of the contract to the sender account.
   */
  constructor()
    public
  {
    owner = msg.sender;
  }

  /**
   * @dev Throws if called by any account other than the owner.
   */
  modifier onlyOwner()
  {
    require(msg.sender == owner, NOT_OWNER);
    _;
  }

  /**
   * @dev Allows the current owner to transfer control of the contract to a newOwner.
   * @param _newOwner The address to transfer ownership to.
   */
  function transferOwnership(
    address _newOwner
  )
    public
    onlyOwner
  {
    require(_newOwner != address(0), ZERO_ADDRESS);
    emit OwnershipTransferred(owner, _newOwner);
    owner = _newOwner;
  }

}

// File: contracts/tokens/Pausable.sol

pragma solidity 0.5.6;

/**
 * @title Pausable
 * @dev Base contract which allows children to implement an emergency stop mechanism.
 */
contract Pausable is Ownable {
    event Pause();
    event Unpause();

    bool public paused = false;

    constructor() public {
        Ownable(msg.sender);
    }


    /**
     * @dev Modifier to make a function callable only when the contract is not paused.
     */
    modifier whenNotPaused() {
        require(!paused);
        _;
    }

    /**
     * @dev Modifier to make a function callable only when the contract is paused.
     */
    modifier whenPaused() {
        require(paused);
        _;
    }

    /**
     * @dev called by the owner to pause, triggers stopped state
     */
    function pause() onlyOwner whenNotPaused public {
        paused = true;
        emit Pause();
    }

    /**
     * @dev called by the owner to unpause, returns to normal state
     */
    function unpause() onlyOwner whenPaused public {
        paused = false;
        emit Unpause();
    }
}

// File: contracts/tokens/ECDSA.sol

pragma solidity 0.5.6;

/**
 * @dev Elliptic Curve Digital Signature Algorithm (ECDSA) operations.
 *
 * These functions can be used to verify that a message was signed by the holder
 * of the private keys of a given address.
 */
library ECDSA {
    /**
     * @dev Returns the address that signed a hashed message (`hash`) with
     * `signature`. This address can then be used for verification purposes.
     *
     * The `ecrecover` EVM opcode allows for malleable (non-unique) signatures:
     * this function rejects them by requiring the `s` value to be in the lower
     * half order, and the `v` value to be either 27 or 28.
     *
     * (.note) This call _does not revert_ if the signature is invalid, or
     * if the signer is otherwise unable to be retrieved. In those scenarios,
     * the zero address is returned.
     *
     * (.warning) `hash` _must_ be the result of a hash operation for the
     * verification to be secure: it is possible to craft signatures that
     * recover to arbitrary addresses for non-hashed data. A safe way to ensure
     * this is by receiving a hash of the original message (which may otherwise)
     * be too long), and then calling `toEthSignedMessageHash` on it.
     */
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        // Check the signature length
        if (signature.length != 65) {
            return (address(0));
        }

        // Divide the signature in r, s and v variables
        bytes32 r;
        bytes32 s;
        uint8 v;

        // ecrecover takes the signature parameters, and the only way to get them
        // currently is to use assembly.
        // solhint-disable-next-line no-inline-assembly
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }

        // EIP-2 still allows signature malleability for ecrecover(). Remove this possibility and make the signature
        // unique. Appendix F in the Ethereum Yellow paper (https://ethereum.github.io/yellowpaper/paper.pdf), defines
        // the valid range for s in (281): 0 < s < secp256k1n ÷ 2 + 1, and for v in (282): v ∈ {27, 28}. Most
        // signatures from current libraries generate a unique signature with an s-value in the lower half order.
        //
        // If your library generates malleable signatures, such as s-values in the upper range, calculate a new s-value
        // with 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1 and flip v from 27 to 28 or
        // vice versa. If your library also generates signatures with 0/1 for v instead 27/28, add 27 to v to accept
        // these malleable signatures as well.
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return address(0);
        }

        if (v != 27 && v != 28) {
            return address(0);
        }

        // If the signature is valid (and not malleable), return the signer address
        return ecrecover(hash, v, r, s);
    }

    /**
     * @dev Returns an Ethereum Signed Message, created from a `hash`. This
     * replicates the behavior of the
     * [`eth_sign`](https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_sign)
     * JSON-RPC method.
     *
     * See `recover`.
     */
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        // 32 is the length in bytes of hash,
        // enforced by the type signature above
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }
}

// File: @0xcert/ethereum-erc721-contracts/src/contracts/erc721.sol

pragma solidity 0.5.6;

/**
 * @dev ERC-721 non-fungible token standard.
 * See https://github.com/ethereum/EIPs/blob/master/EIPS/eip-721.md.
 */
interface ERC721
{

  /**
   * @dev Emits when ownership of any NFT changes by any mechanism. This event emits when NFTs are
   * created (`from` == 0) and destroyed (`to` == 0). Exception: during contract creation, any
   * number of NFTs may be created and assigned without emitting Transfer. At the time of any
   * transfer, the approved address for that NFT (if any) is reset to none.
   */
  event Transfer(
    address indexed _from,
    address indexed _to,
    uint256 indexed _tokenId
  );

  /**
   * @dev This emits when the approved address for an NFT is changed or reaffirmed. The zero
   * address indicates there is no approved address. When a Transfer event emits, this also
   * indicates that the approved address for that NFT (if any) is reset to none.
   */
  event Approval(
    address indexed _owner,
    address indexed _approved,
    uint256 indexed _tokenId
  );

  /**
   * @dev This emits when an operator is enabled or disabled for an owner. The operator can manage
   * all NFTs of the owner.
   */
  event ApprovalForAll(
    address indexed _owner,
    address indexed _operator,
    bool _approved
  );

  /**
   * @dev Transfers the ownership of an NFT from one address to another address.
   * @notice Throws unless `msg.sender` is the current owner, an authorized operator, or the
   * approved address for this NFT. Throws if `_from` is not the current owner. Throws if `_to` is
   * the zero address. Throws if `_tokenId` is not a valid NFT. When transfer is complete, this
   * function checks if `_to` is a smart contract (code size > 0). If so, it calls
   * `onERC721Received` on `_to` and throws if the return value is not
   * `bytes4(keccak256("onERC721Received(address,uint256,bytes)"))`.
   * @param _from The current owner of the NFT.
   * @param _to The new owner.
   * @param _tokenId The NFT to transfer.
   * @param _data Additional data with no specified format, sent in call to `_to`.
   */
  function safeTransferFrom(
    address _from,
    address _to,
    uint256 _tokenId,
    bytes calldata _data
  )
    external;

  /**
   * @dev Transfers the ownership of an NFT from one address to another address.
   * @notice This works identically to the other function with an extra data parameter, except this
   * function just sets data to ""
   * @param _from The current owner of the NFT.
   * @param _to The new owner.
   * @param _tokenId The NFT to transfer.
   */
  function safeTransferFrom(
    address _from,
    address _to,
    uint256 _tokenId
  )
    external;

  /**
   * @dev Throws unless `msg.sender` is the current owner, an authorized operator, or the approved
   * address for this NFT. Throws if `_from` is not the current owner. Throws if `_to` is the zero
   * address. Throws if `_tokenId` is not a valid NFT.
   * @notice The caller is responsible to confirm that `_to` is capable of receiving NFTs or else
   * they mayb be permanently lost.
   * @param _from The current owner of the NFT.
   * @param _to The new owner.
   * @param _tokenId The NFT to transfer.
   */
  function transferFrom(
    address _from,
    address _to,
    uint256 _tokenId
  )
    external;

  /**
   * @dev Set or reaffirm the approved address for an NFT.
   * @notice The zero address indicates there is no approved address. Throws unless `msg.sender` is
   * the current NFT owner, or an authorized operator of the current owner.
   * @param _approved The new approved NFT controller.
   * @param _tokenId The NFT to approve.
   */
  function approve(
    address _approved,
    uint256 _tokenId
  )
    external;

  /**
   * @dev Enables or disables approval for a third party ("operator") to manage all of
   * `msg.sender`'s assets. It also emits the ApprovalForAll event.
   * @notice The contract MUST allow multiple operators per owner.
   * @param _operator Address to add to the set of authorized operators.
   * @param _approved True if the operators is approved, false to revoke approval.
   */
  function setApprovalForAll(
    address _operator,
    bool _approved
  )
    external;

  /**
   * @dev Returns the number of NFTs owned by `_owner`. NFTs assigned to the zero address are
   * considered invalid, and this function throws for queries about the zero address.
   * @param _owner Address for whom to query the balance.
   * @return Balance of _owner.
   */
  function balanceOf(
    address _owner
  )
    external
    view
    returns (uint256);

  /**
   * @dev Returns the address of the owner of the NFT. NFTs assigned to zero address are considered
   * invalid, and queries about them do throw.
   * @param _tokenId The identifier for an NFT.
   * @return Address of _tokenId owner.
   */
  function ownerOf(
    uint256 _tokenId
  )
    external
    view
    returns (address);

  /**
   * @dev Get the approved address for a single NFT.
   * @notice Throws if `_tokenId` is not a valid NFT.
   * @param _tokenId The NFT to find the approved address for.
   * @return Address that _tokenId is approved for.
   */
  function getApproved(
    uint256 _tokenId
  )
    external
    view
    returns (address);

  /**
   * @dev Returns true if `_operator` is an approved operator for `_owner`, false otherwise.
   * @param _owner The address that owns the NFTs.
   * @param _operator The address that acts on behalf of the owner.
   * @return True if approved for all, false otherwise.
   */
  function isApprovedForAll(
    address _owner,
    address _operator
  )
    external
    view
    returns (bool);

}

// File: @0xcert/ethereum-erc721-contracts/src/contracts/erc721-metadata.sol

pragma solidity 0.5.6;

/**
 * @dev Optional metadata extension for ERC-721 non-fungible token standard.
 * See https://github.com/ethereum/EIPs/blob/master/EIPS/eip-721.md.
 */
interface ERC721Metadata
{

  /**
   * @dev Returns a descriptive name for a collection of NFTs in this contract.
   * @return Representing name.
   */
  function name()
    external
    view
    returns (string memory _name);

  /**
   * @dev Returns a abbreviated name for a collection of NFTs in this contract.
   * @return Representing symbol.
   */
  function symbol()
    external
    view
    returns (string memory _symbol);

  /**
   * @dev Returns a distinct Uniform Resource Identifier (URI) for a given asset. It Throws if
   * `_tokenId` is not a valid NFT. URIs are defined in RFC3986. The URI may point to a JSON file
   * that conforms to the "ERC721 Metadata JSON Schema".
   * @return URI of _tokenId.
   */
  function tokenURI(uint256 _tokenId)
    external
    view
    returns (string memory);

}

// File: @0xcert/ethereum-erc721-contracts/src/contracts/erc721-enumerable.sol

pragma solidity 0.5.6;

/**
 * @dev Optional enumeration extension for ERC-721 non-fungible token standard.
 * See https://github.com/ethereum/EIPs/blob/master/EIPS/eip-721.md.
 */
interface ERC721Enumerable
{

  /**
   * @dev Returns a count of valid NFTs tracked by this contract, where each one of them has an
   * assigned and queryable owner not equal to the zero address.
   * @return Total supply of NFTs.
   */
  function totalSupply()
    external
    view
    returns (uint256);

  /**
   * @dev Returns the token identifier for the `_index`th NFT. Sort order is not specified.
   * @param _index A counter less than `totalSupply()`.
   * @return Token id.
   */
  function tokenByIndex(
    uint256 _index
  )
    external
    view
    returns (uint256);

  /**
   * @dev Returns the token identifier for the `_index`th NFT assigned to `_owner`. Sort order is
   * not specified. It throws if `_index` >= `balanceOf(_owner)` or if `_owner` is the zero address,
   * representing invalid NFTs.
   * @param _owner An address where we are interested in NFTs owned by them.
   * @param _index A counter less than `balanceOf(_owner)`.
   * @return Token id.
   */
  function tokenOfOwnerByIndex(
    address _owner,
    uint256 _index
  )
    external
    view
    returns (uint256);

}

// File: @0xcert/ethereum-erc721-contracts/src/contracts/erc721-token-receiver.sol

pragma solidity 0.5.6;

/**
 * @dev ERC-721 interface for accepting safe transfers.
 * See https://github.com/ethereum/EIPs/blob/master/EIPS/eip-721.md.
 */
interface ERC721TokenReceiver
{

  /**
   * @dev Handle the receipt of a NFT. The ERC721 smart contract calls this function on the
   * recipient after a `transfer`. This function MAY throw to revert and reject the transfer. Return
   * of other than the magic value MUST result in the transaction being reverted.
   * Returns `bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))` unless throwing.
   * @notice The contract address is always the message sender. A wallet/broker/auction application
   * MUST implement the wallet interface if it will accept safe transfers.
   * @param _operator The address which called `safeTransferFrom` function.
   * @param _from The address which previously owned the token.
   * @param _tokenId The NFT identifier which is being transferred.
   * @param _data Additional data with no specified format.
   * @return Returns `bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))`.
   */
  function onERC721Received(
    address _operator,
    address _from,
    uint256 _tokenId,
    bytes calldata _data
  )
    external
    returns(bytes4);

}

// File: @0xcert/ethereum-utils-contracts/src/contracts/utils/erc165.sol

pragma solidity 0.5.6;

/**
 * @dev A standard for detecting smart contract interfaces.
 * See: https://eips.ethereum.org/EIPS/eip-165.
 */
interface ERC165
{

  /**
   * @dev Checks if the smart contract implements a specific interface.
   * @notice This function uses less than 30,000 gas.
   * @param _interfaceID The interface identifier, as specified in ERC-165.
   */
  function supportsInterface(
    bytes4 _interfaceID
  )
    external
    view
    returns (bool);

}

// File: @0xcert/ethereum-utils-contracts/src/contracts/utils/supports-interface.sol

pragma solidity 0.5.6;


/**
 * @dev Implementation of standard to publish supported interfaces.
 */
contract SupportsInterface is
  ERC165
{

  /**
   * @dev Mapping of supported intefraces.
   * @notice You must not set element 0xffffffff to true.
   */
  mapping(bytes4 => bool) internal supportedInterfaces;

  /**
   * @dev Contract constructor.
   */
  constructor()
    public
  {
    supportedInterfaces[0x01ffc9a7] = true; // ERC165
  }

  /**
   * @dev Function to check which interfaces are suported by this contract.
   * @param _interfaceID Id of the interface.
   */
  function supportsInterface(
    bytes4 _interfaceID
  )
    external
    view
    returns (bool)
  {
    return supportedInterfaces[_interfaceID];
  }

}

// File: @0xcert/ethereum-utils-contracts/src/contracts/utils/address-utils.sol

pragma solidity 0.5.6;

/**
 * @dev Utility library of inline functions on addresses.
 */
library AddressUtils
{

  /**
   * @dev Returns whether the target address is a contract.
   * @param _addr Address to check.
   * @return True if _addr is a contract, false if not.
   */
  function isContract(
    address _addr
  )
    internal
    view
    returns (bool addressCheck)
  {
    uint256 size;

    /**
     * XXX Currently there is no better way to check if there is a contract in an address than to
     * check the size of the code at that address.
     * See https://ethereum.stackexchange.com/a/14016/36603 for more details about how this works.
     * TODO: Check this again before the Serenity release, because all addresses will be
     * contracts then.
     */
    assembly { size := extcodesize(_addr) } // solhint-disable-line
    addressCheck = size > 0;
  }

}

// File: @0xcert/ethereum-erc721-contracts/src/contracts/nf-token-metadata-enumerable.sol

pragma solidity 0.5.6;








/**
 * @dev Optional metadata enumerable implementation for ERC-721 non-fungible token standard.
 */
contract NFTokenMetadataEnumerable is
  ERC721,
  ERC721Metadata,
  ERC721Enumerable,
  SupportsInterface
{
  using SafeMath for uint256;
  using AddressUtils for address;

  /**
   * @dev Error constants.
   */
  string constant ZERO_ADDRESS = "006001";
  string constant NOT_VALID_NFT = "006002";
  string constant NOT_OWNER_OR_OPERATOR = "006003";
  string constant NOT_OWNER_APPROWED_OR_OPERATOR = "006004";
  string constant NOT_ABLE_TO_RECEIVE_NFT = "006005";
  string constant NFT_ALREADY_EXISTS = "006006";
  string constant INVALID_INDEX = "006007";

  /**
   * @dev Magic value of a smart contract that can recieve NFT.
   * Equal to: bytes4(keccak256("onERC721Received(address,address,uint256,bytes)")).
   */
  bytes4 constant MAGIC_ON_ERC721_RECEIVED = 0x150b7a02;

  /**
   * @dev A descriptive name for a collection of NFTs.
   */
  string internal nftName;

  /**
   * @dev An abbreviated name for NFTs.
   */
  string internal nftSymbol;

  /**
   * @dev URI base for NFT metadata. NFT URI is made from base + NFT id.
   */
  string public uriBase;

  /**
   * @dev Array of all NFT IDs.
   */
  uint256[] internal tokens;

  /**
   * @dev Mapping from token ID its index in global tokens array.
   */
  mapping(uint256 => uint256) internal idToIndex;

  /**
   * @dev Mapping from owner to list of owned NFT IDs.
   */
  mapping(address => uint256[]) internal ownerToIds;

  /**
   * @dev Mapping from NFT ID to its index in the owner tokens list.
   */
  mapping(uint256 => uint256) internal idToOwnerIndex;

  /**
   * @dev A mapping from NFT ID to the address that owns it.
   */
  mapping (uint256 => address) internal idToOwner;

  /**
   * @dev Mapping from NFT ID to approved address.
   */
  mapping (uint256 => address) internal idToApproval;

  /**
   * @dev Mapping from owner address to mapping of operator addresses.
   */
  mapping (address => mapping (address => bool)) internal ownerToOperators;

  /**
   * @dev Emits when ownership of any NFT changes by any mechanism. This event emits when NFTs are
   * created (`from` == 0) and destroyed (`to` == 0). Exception: during contract creation, any
   * number of NFTs may be created and assigned without emitting Transfer. At the time of any
   * transfer, the approved address for that NFT (if any) is reset to none.
   * @param _from Sender of NFT (if address is zero address it indicates token creation).
   * @param _to Receiver of NFT (if address is zero address it indicates token destruction).
   * @param _tokenId The NFT that got transfered.
   */
  event Transfer(
    address indexed _from,
    address indexed _to,
    uint256 indexed _tokenId
  );

  /**
   * @dev This emits when the approved address for an NFT is changed or reaffirmed. The zero
   * address indicates there is no approved address. When a Transfer event emits, this also
   * indicates that the approved address for that NFT (if any) is reset to none.
   * @param _owner Owner of NFT.
   * @param _approved Address that we are approving.
   * @param _tokenId NFT which we are approving.
   */
  event Approval(
    address indexed _owner,
    address indexed _approved,
    uint256 indexed _tokenId
  );

  /**
   * @dev This emits when an operator is enabled or disabled for an owner. The operator can manage
   * all NFTs of the owner.
   * @param _owner Owner of NFT.
   * @param _operator Address to which we are setting operator rights.
   * @param _approved Status of operator rights(true if operator rights are given and false if
   * revoked).
   */
  event ApprovalForAll(
    address indexed _owner,
    address indexed _operator,
    bool _approved
  );

  /**
   * @dev Contract constructor.
   * @notice When implementing this contract don't forget to set nftName, nftSymbol and uriBase.
   */
  constructor()
    public
  {
    supportedInterfaces[0x80ac58cd] = true; // ERC721
    supportedInterfaces[0x5b5e139f] = true; // ERC721Metadata
    supportedInterfaces[0x780e9d63] = true; // ERC721Enumerable
  }

  /**
   * @dev Transfers the ownership of an NFT from one address to another address.
   * @notice Throws unless `msg.sender` is the current owner, an authorized operator, or the
   * approved address for this NFT. Throws if `_from` is not the current owner. Throws if `_to` is
   * the zero address. Throws if `_tokenId` is not a valid NFT. When transfer is complete, this
   * function checks if `_to` is a smart contract (code size > 0). If so, it calls
   * `onERC721Received` on `_to` and throws if the return value is not
   * `bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))`.
   * @param _from The current owner of the NFT.
   * @param _to The new owner.
   * @param _tokenId The NFT to transfer.
   * @param _data Additional data with no specified format, sent in call to `_to`.
   */
  function safeTransferFrom(
    address _from,
    address _to,
    uint256 _tokenId,
    bytes calldata _data
  )
    external
  {
    _safeTransferFrom(_from, _to, _tokenId, _data);
  }

  /**
   * @dev Transfers the ownership of an NFT from one address to another address.
   * @notice This works identically to the other function with an extra data parameter, except this
   * function just sets data to "".
   * @param _from The current owner of the NFT.
   * @param _to The new owner.
   * @param _tokenId The NFT to transfer.
   */
  function safeTransferFrom(
    address _from,
    address _to,
    uint256 _tokenId
  )
    external
  {
    _safeTransferFrom(_from, _to, _tokenId, "");
  }

  /**
   * @dev Throws unless `msg.sender` is the current owner, an authorized operator, or the approved
   * address for this NFT. Throws if `_from` is not the current owner. Throws if `_to` is the zero
   * address. Throws if `_tokenId` is not a valid NFT.
   * @notice The caller is responsible to confirm that `_to` is capable of receiving NFTs or else
   * they maybe be permanently lost.
   * @param _from The current owner of the NFT.
   * @param _to The new owner.
   * @param _tokenId The NFT to transfer.
   */
  function transferFrom(
    address _from,
    address _to,
    uint256 _tokenId
  )
    external
  {
    _transferFrom(_from, _to, _tokenId);
  }

  /**
   * @dev Set or reaffirm the approved address for an NFT.
   * @notice The zero address indicates there is no approved address. Throws unless `msg.sender` is
   * the current NFT owner, or an authorized operator of the current owner.
   * @param _approved Address to be approved for the given NFT ID.
   * @param _tokenId ID of the token to be approved.
   */
  function approve(
    address _approved,
    uint256 _tokenId
  )
    external
  {
    // can operate
    address tokenOwner = idToOwner[_tokenId];
    require(
      tokenOwner == msg.sender || ownerToOperators[tokenOwner][msg.sender],
      NOT_OWNER_OR_OPERATOR
    );

    idToApproval[_tokenId] = _approved;
    emit Approval(tokenOwner, _approved, _tokenId);
  }

  /**
   * @dev Enables or disables approval for a third party ("operator") to manage all of
   * `msg.sender`'s assets. It also emits the ApprovalForAll event.
   * @notice This works even if sender doesn't own any tokens at the time.
   * @param _operator Address to add to the set of authorized operators.
   * @param _approved True if the operators is approved, false to revoke approval.
   */
  function setApprovalForAll(
    address _operator,
    bool _approved
  )
    external
  {
    ownerToOperators[msg.sender][_operator] = _approved;
    emit ApprovalForAll(msg.sender, _operator, _approved);
  }

  /**
   * @dev Returns the number of NFTs owned by `_owner`. NFTs assigned to the zero address are
   * considered invalid, and this function throws for queries about the zero address.
   * @param _owner Address for whom to query the balance.
   * @return Balance of _owner.
   */
  function balanceOf(
    address _owner
  )
    external
    view
    returns (uint256)
  {
    require(_owner != address(0), ZERO_ADDRESS);
    return ownerToIds[_owner].length;
  }

  /**
   * @dev Returns the address of the owner of the NFT. NFTs assigned to zero address are considered
   * invalid, and queries about them do throw.
   * @param _tokenId The identifier for an NFT.
   * @return Address of _tokenId owner.
   */
  function ownerOf(
    uint256 _tokenId
  )
    external
    view
    returns (address _owner)
  {
    _owner = idToOwner[_tokenId];
    require(_owner != address(0), NOT_VALID_NFT);
  }

  /**
   * @dev Get the approved address for a single NFT.
   * @notice Throws if `_tokenId` is not a valid NFT.
   * @param _tokenId ID of the NFT to query the approval of.
   * @return Address that _tokenId is approved for.
   */
  function getApproved(
    uint256 _tokenId
  )
    external
    view
    returns (address)
  {
    require(idToOwner[_tokenId] != address(0), NOT_VALID_NFT);
    return idToApproval[_tokenId];
  }

  /**
   * @dev Checks if `_operator` is an approved operator for `_owner`.
   * @param _owner The address that owns the NFTs.
   * @param _operator The address that acts on behalf of the owner.
   * @return True if approved for all, false otherwise.
   */
  function isApprovedForAll(
    address _owner,
    address _operator
  )
    external
    view
    returns (bool)
  {
    return ownerToOperators[_owner][_operator];
  }

  /**
   * @dev Returns the count of all existing NFTs.
   * @return Total supply of NFTs.
   */
  function totalSupply()
    external
    view
    returns (uint256)
  {
    return tokens.length;
  }

  /**
   * @dev Returns NFT ID by its index.
   * @param _index A counter less than `totalSupply()`.
   * @return Token id.
   */
  function tokenByIndex(
    uint256 _index
  )
    external
    view
    returns (uint256)
  {
    require(_index < tokens.length, INVALID_INDEX);
    return tokens[_index];
  }

  /**
   * @dev returns the n-th NFT ID from a list of owner's tokens.
   * @param _owner Token owner's address.
   * @param _index Index number representing n-th token in owner's list of tokens.
   * @return Token id.
   */
  function tokenOfOwnerByIndex(
    address _owner,
    uint256 _index
  )
    external
    view
    returns (uint256)
  {
    require(_index < ownerToIds[_owner].length, INVALID_INDEX);
    return ownerToIds[_owner][_index];
  }

  /**
   * @dev Returns a descriptive name for a collection of NFTs.
   * @return Representing name.
   */
  function name()
    external
    view
    returns (string memory _name)
  {
    _name = nftName;
  }

  /**
   * @dev Returns an abbreviated name for NFTs.
   * @return Representing symbol.
   */
  function symbol()
    external
    view
    returns (string memory _symbol)
  {
    _symbol = nftSymbol;
  }

  /**
   * @notice A distinct Uniform Resource Identifier (URI) for a given asset.
   * @dev Throws if `_tokenId` is not a valid NFT. URIs are defined in RFC 3986. The URI may point
   * to a JSON file that conforms to the "ERC721 Metadata JSON Schema".
   * @param _tokenId Id for which we want URI.
   * @return URI of _tokenId.
   */
  function tokenURI(
    uint256 _tokenId
  )
    external
    view
    returns (string memory)
  {
    require(idToOwner[_tokenId] != address(0), NOT_VALID_NFT);
    if (bytes(uriBase).length > 0)
    {
      return string(abi.encodePacked(uriBase, _uint2str(_tokenId)));
    }
    return "";
  }

  /**
   * @dev Set a distinct URI (RFC 3986) base for all nfts.
   * @notice this is a internal function which should be called from user-implemented external
   * function. Its purpose is to show and properly initialize data structures when using this
   * implementation.
   * @param _uriBase String representing RFC 3986 URI base.
   */
  function _setUriBase(
    string memory _uriBase
  )
    internal
  {
    uriBase = _uriBase;
  }

  /**
   * @dev Creates a new NFT.
   * @notice This is a private function which should be called from user-implemented external
   * function. Its purpose is to show and properly initialize data structures when using this
   * implementation.
   * @param _to The address that will own the created NFT.
   * @param _tokenId of the NFT to be created by the msg.sender.
   */
  function _create(
    address _to,
    uint256 _tokenId
  )
    internal
  {
    require(_to != address(0), ZERO_ADDRESS);
    require(idToOwner[_tokenId] == address(0), NFT_ALREADY_EXISTS);

    // add NFT
    idToOwner[_tokenId] = _to;

    uint256 length = ownerToIds[_to].push(_tokenId);
    idToOwnerIndex[_tokenId] = length - 1;

    // add to tokens array
    length = tokens.push(_tokenId);
    idToIndex[_tokenId] = length - 1;

    emit Transfer(address(0), _to, _tokenId);
  }

  /**
   * @dev Destroys a NFT.
   * @notice This is a private function which should be called from user-implemented external
   * destroy function. Its purpose is to show and properly initialize data structures when using this
   * implementation.
   * @param _tokenId ID of the NFT to be destroyed.
   */
  function _destroy(
    uint256 _tokenId
  )
    internal
  {
    // valid NFT
    address owner = idToOwner[_tokenId];
    require(owner != address(0), NOT_VALID_NFT);

    // clear approval
    if (idToApproval[_tokenId] != address(0))
    {
      delete idToApproval[_tokenId];
    }

    // remove NFT
    assert(ownerToIds[owner].length > 0);

    uint256 tokenToRemoveIndex = idToOwnerIndex[_tokenId];
    uint256 lastTokenIndex = ownerToIds[owner].length - 1;
    uint256 lastToken;
    if (lastTokenIndex != tokenToRemoveIndex)
    {
      lastToken = ownerToIds[owner][lastTokenIndex];
      ownerToIds[owner][tokenToRemoveIndex] = lastToken;
      idToOwnerIndex[lastToken] = tokenToRemoveIndex;
    }

    delete idToOwner[_tokenId];
    delete idToOwnerIndex[_tokenId];
    ownerToIds[owner].length--;

    // remove from tokens array
    assert(tokens.length > 0);

    uint256 tokenIndex = idToIndex[_tokenId];
    lastTokenIndex = tokens.length - 1;
    lastToken = tokens[lastTokenIndex];

    tokens[tokenIndex] = lastToken;

    tokens.length--;
    // Consider adding a conditional check for the last token in order to save GAS.
    idToIndex[lastToken] = tokenIndex;
    idToIndex[_tokenId] = 0;

    emit Transfer(owner, address(0), _tokenId);
  }

  /**
   * @dev Helper methods that actually does the transfer.
   * @param _from The current owner of the NFT.
   * @param _to The new owner.
   * @param _tokenId The NFT to transfer.
   */
  function _transferFrom(
    address _from,
    address _to,
    uint256 _tokenId
  )
    internal
  {
    // valid NFT
    require(_from != address(0), ZERO_ADDRESS);
    require(idToOwner[_tokenId] == _from, NOT_VALID_NFT);
    require(_to != address(0), ZERO_ADDRESS);

    // can transfer
    require(
      _from == msg.sender
      || idToApproval[_tokenId] == msg.sender
      || ownerToOperators[_from][msg.sender],
      NOT_OWNER_APPROWED_OR_OPERATOR
    );

    // clear approval
    if (idToApproval[_tokenId] != address(0))
    {
      delete idToApproval[_tokenId];
    }

    // remove NFT
    assert(ownerToIds[_from].length > 0);

    uint256 tokenToRemoveIndex = idToOwnerIndex[_tokenId];
    uint256 lastTokenIndex = ownerToIds[_from].length - 1;

    if (lastTokenIndex != tokenToRemoveIndex)
    {
      uint256 lastToken = ownerToIds[_from][lastTokenIndex];
      ownerToIds[_from][tokenToRemoveIndex] = lastToken;
      idToOwnerIndex[lastToken] = tokenToRemoveIndex;
    }

    ownerToIds[_from].length--;

    // add NFT
    idToOwner[_tokenId] = _to;
    uint256 length = ownerToIds[_to].push(_tokenId);
    idToOwnerIndex[_tokenId] = length - 1;

    emit Transfer(_from, _to, _tokenId);
  }

  /**
   * @dev Helper function that actually does the safeTransfer.
   * @param _from The current owner of the NFT.
   * @param _to The new owner.
   * @param _tokenId The NFT to transfer.
   * @param _data Additional data with no specified format, sent in call to `_to`.
   */
  function _safeTransferFrom(
    address _from,
    address _to,
    uint256 _tokenId,
    bytes memory _data
  )
    internal
  {
    if (_to.isContract())
    {
      require(
        ERC721TokenReceiver(_to)
          .onERC721Received(msg.sender, _from, _tokenId, _data) == MAGIC_ON_ERC721_RECEIVED,
        NOT_ABLE_TO_RECEIVE_NFT
      );
    }

    _transferFrom(_from, _to, _tokenId);
  }

  /**
   * @dev Helper function that changes uint to string representation.
   * @return String representation.
   */
  function _uint2str(
    uint256 _i
  )
    internal
    pure
    returns (string memory str)
  {
    if (_i == 0)
    {
      return "0";
    }
    uint256 j = _i;
    uint256 length;
    while (j != 0)
    {
      length++;
      j /= 10;
    }
    bytes memory bstr = new bytes(length);
    uint256 k = length - 1;
    j = _i;
    while (j != 0)
    {
      bstr[k--] = byte(uint8(48 + j % 10));
      j /= 10;
    }
    str = string(bstr);
  }

}

// File: contracts/tokens/ArianeeSmartAsset.sol

pragma solidity 0.5.6;

contract ArianeeWhitelist {
  function addWhitelistedAddress(uint256 _tokenId, address _address) external;
}


contract ArianeeStore{
    function canTransfer(address _to,address _from,uint256 _tokenId) external returns(bool);
    function canDestroy(uint256 _tokenId, address _sender) external returns(bool);
}






/// @title Contract handling Arianee Certificates.
contract ArianeeSmartAsset is
NFTokenMetadataEnumerable,
Abilitable,
Ownable,
Pausable
{

  /**
   * @dev Mapping from token id to URI.
   */
  mapping(uint256 => string) internal idToUri;

  /**
   * @dev Mapping from token id to Token Access (0=view, 1=transfer).
   */
  mapping(uint256 => mapping(uint256 => address)) internal tokenAccess;

  /**
   * @dev Mapping from token id to TokenImprintUpdate.
   */
  mapping(uint256 => bytes32) internal idToImprint;

  /**
   * @dev Mapping from token id to recovery request bool.
   */
  mapping(uint256=>bool) internal recoveryRequest;

  /**
   * @dev Mapping from token id to total rewards for this NFT.
   */
  mapping(uint256=>uint256) internal rewards;

  /**
   * @dev Mapping from token id to Cert.
   */
  mapping(uint256 => Cert) internal certificate;

  /**
   * @dev This emits when a new address is set.
   */
  event SetAddress(string _addressType, address _newAddress);

  struct Cert {
      address tokenIssuer;
      uint256 tokenCreationDate;
      uint256 tokenRecoveryTimestamp;
  }

  /**
   * @dev Ability to create and hydrate NFT.
   */
  uint8 constant ABILITY_CREATE_ASSET = 2;

  /**
   * @dev Error constants.
   */
  string constant CAPABILITY_NOT_SUPPORTED = "007001";
  string constant TRANSFERS_DISABLED = "007002";
  string constant NOT_VALID_XCERT = "007003";
  string constant NFT_ALREADY_SET = "007006";
  string constant NOT_OWNER_OR_OPERATOR = "007004";

  /**
   * Interface for all the connected contracts.
   */
  ArianeeWhitelist arianeeWhitelist;
  ArianeeStore store;

  /**
   * @dev This emits when a token is hydrated.
   */
  event Hydrated(uint256 _tokenId, bytes32 _imprint, string _uri, address _initialKey, uint256 _tokenRecoveryTimestamp, bool _initialKeyIsRequestKey, uint256 _tokenCreation);

  /**
   * @dev This emits when a issuer request a NFT recovery.
   */
  event RecoveryRequestUpdated(uint256 _tokenId, bool _active);

  /**
   * @dev This emits when a NFT is recovered to the issuer.
   */
  event TokenRecovered(uint256 _token);

  /**
   * @dev This emits when a NFT's URI is udpated.
   */
  event TokenURIUpdated(uint256 _tokenId, string URI);

  /**
   * @dev This emits when a token access is added.
   */
  event TokenAccessAdded(uint256 _tokenId, address _encryptedTokenKey, bool _enable, uint256 _tokenType);

  /**
   * @dev This emits when a token access is destroyed.
   */
  event TokenDestroyed(uint256 _tokenId);

  /**
   * @dev This emits when the uri base is udpated.
   */
  event SetNewUriBase(string _newUriBase);


  /**
   * @dev Check if the msg.sender can operate the NFT.
   * @param _tokenId ID of the NFT to test.
   * @param _operator Address to test.
   */
  modifier isOperator(uint256 _tokenId, address _operator) {
    require(canOperate(_tokenId, _operator), NOT_OWNER_OR_OPERATOR);
    _;
  }

  /**
   * @dev Check if msg.sender is the issuer of a NFT.
   * @param _tokenId ID of the NFT to test.
   */
   modifier isIssuer(uint256 _tokenId) {
    require(msg.sender == certificate[_tokenId].tokenIssuer);
    _;
   }

  /**
    * @dev Initialize this contract. Acts as a constructor
    * @param _arianeeWhitelistAddress Adress of the whitelist contract.
    */
  constructor(
    address _arianeeWhitelistAddress
  )
  public
  {
    nftName = "Arianee Smart-Asset";
    nftSymbol = "AriaSA";
    setWhitelistAddress(_arianeeWhitelistAddress);
    _setUriBase("https://cert.arianee.org/");
  }

  /**
   * @notice Change address of the store infrastructure.
   * @param _storeAddress new address of the store.
   */
  function setStoreAddress(address _storeAddress) external onlyOwner(){
    store = ArianeeStore(address(_storeAddress));
    emit SetAddress("storeAddress", _storeAddress);
  }

  /**
   * @notice Reserve a NFT at the given ID.
   * @dev Has to be called through an authorized contract.
   * @dev Can only be called by an authorized address.
   * @param _tokenId ID to reserve.
   * @param _to receiver of the token.
   * @param _rewards total rewards of this NFT.
   */
  function reserveToken(uint256 _tokenId, address _to, uint256 _rewards) external hasAbilities(ABILITY_CREATE_ASSET) whenNotPaused() {
    super._create(_to, _tokenId);
    rewards[_tokenId] = _rewards;
  }

  /**
   * @notice Recover the NFT to the issuer.
   * @dev only if called by the issuer and if called before the token Recovery Timestamp of the NFT.
   * @param _tokenId ID of the NFT to recover.
   */
  function recoverTokenToIssuer(uint256 _tokenId) external whenNotPaused() isIssuer(_tokenId) {
    require(block.timestamp < certificate[_tokenId].tokenRecoveryTimestamp);
    idToApproval[_tokenId] = certificate[_tokenId].tokenIssuer;
    _transferFrom(idToOwner[_tokenId], certificate[_tokenId].tokenIssuer, _tokenId);

    emit TokenRecovered(_tokenId);
  }

  /**
   * @notice Update a recovery request (doesn't transfer the NFT).
   * @dev Works only if called by the issuer.
   * @param _tokenId ID of the NFT to recover.
   * @param _active boolean to active or unactive the request.
   */
  function updateRecoveryRequest(uint256 _tokenId, bool _active) external whenNotPaused() isIssuer(_tokenId){
    recoveryRequest[_tokenId] = _active;

    emit RecoveryRequestUpdated(_tokenId, _active);
  }

  /**
   * @notice Valid a recovery request and transfer the NFT to the issuer.
   * @dev only if the request is active and if called by the owner of the contract.
   * @param _tokenId Id of the NFT to recover.
   */
  function validRecoveryRequest(uint256 _tokenId) external onlyOwner(){
    require(recoveryRequest[_tokenId]);
    recoveryRequest[_tokenId] = false;

    idToApproval[_tokenId] = owner;
    _transferFrom(idToOwner[_tokenId], certificate[_tokenId].tokenIssuer, _tokenId);

    emit RecoveryRequestUpdated(_tokenId, false);
    emit TokenRecovered(_tokenId);
  }

  /**
   * @notice External function to update the tokenURI.
   * @notice Can only be called by the NFT's issuer.
   * @param _tokenId ID of the NFT to edit.
   * @param _uri New URI for the certificate.
   */
  function updateTokenURI(uint256 _tokenId, string calldata _uri) external isIssuer(_tokenId) whenNotPaused() {
    require(idToOwner[_tokenId] != address(0), NOT_VALID_XCERT);
    idToUri[_tokenId] = _uri;

    emit TokenURIUpdated(_tokenId, _uri);
  }

  /**
   * @notice Add a token access to a NFT.
   * @notice can only be called by an NFT's operator.
   * @param _tokenId ID of the NFT.
   * @param _key Public address of the token to encode the hash with.
   * @param _enable Enable or disable the token access.
   * @param _tokenType Type of token access (0=view, 1=tranfer).
   * @return true.
   */
  function addTokenAccess(uint256 _tokenId, address _key, bool _enable, uint256 _tokenType) external isOperator(_tokenId, msg.sender) whenNotPaused() {
      require(_tokenType>0);
    if (_enable) {
      tokenAccess[_tokenId][_tokenType] = _key;
    }
    else {
      tokenAccess[_tokenId][_tokenType] = address(0);
    }

    emit TokenAccessAdded(_tokenId, _key, _enable, _tokenType);
  }

  /**
   * @notice Transfers the ownership of a NFT to another address
   * @notice Requires to send the correct tokenKey and the NFT has to be requestable
   * @dev Has to be called through an authorized contract.
   * @dev approve the requester if _tokenKey is valid to allow transferFrom without removing ERC721 compliance.
   * @param _tokenId ID of the NFT to transfer.
   * @param _hash Hash of tokenId + newOwner address.
   * @param _keepRequestToken If false erase the access token of the NFT.
   * @param _newOwner Address of the new owner of the NFT.
   * @return total rewards of this NFT.
   */
  function requestToken(uint256 _tokenId, bytes32 _hash, bool _keepRequestToken, address _newOwner, bytes calldata _signature) external hasAbilities(ABILITY_CREATE_ASSET) whenNotPaused() returns(uint256 reward){

    require(isTokenValid(_tokenId, _hash, 1, _signature));
    bytes32 message = keccak256(abi.encode(_tokenId, _newOwner));
    require(ECDSA.toEthSignedMessageHash(message) == _hash);

    idToApproval[_tokenId] = msg.sender;

    if(!_keepRequestToken){
      tokenAccess[_tokenId][1] = address(0);
    }
    _transferFrom(idToOwner[_tokenId], _newOwner, _tokenId);
    reward = rewards[_tokenId];
    delete rewards[_tokenId];
  }

  /**
   * @notice Destroy a token.
   * @notice Can only be called by the issuer.
   * @param _tokenId to destroy.
   */
  function destroy(uint256 _tokenId) external whenNotPaused() {
    require(store.canDestroy(_tokenId, msg.sender));

    _destroy(_tokenId);
    idToImprint[_tokenId] = "";
    idToUri[_tokenId] = "";
    tokenAccess[_tokenId][0] = address(0);
    tokenAccess[_tokenId][1] = address(0);
    rewards[_tokenId] = 0;
    Cert memory _emptyCert = Cert({
             tokenIssuer : address(0),
             tokenCreationDate: 0,
             tokenRecoveryTimestamp: 0
            });

    certificate[_tokenId] = _emptyCert;

    emit TokenDestroyed(_tokenId);
  }

  /**
   * @notice return the URI of a NFT.
   * @param _tokenId uint256 ID of the NFT.
   * @return URI of the NFT.
   */
  function tokenURI(uint256 _tokenId) external view returns (string memory){
      if(bytes(idToUri[_tokenId]).length > 0){
        return idToUri[_tokenId];
      }
      else{
          return string(abi.encodePacked(uriBase, _uint2str(_tokenId)));
      }
  }

  /**
   * @notice Check if a token is requestable.
   * @param _tokenId uint256 ID of the token to check.
   * @return True if the NFT is requestable.
   */
  function isRequestable(uint256 _tokenId) external view returns (bool) {
    return tokenAccess[_tokenId][1] != address(0);
  }

  /**
   * @notice The issuer address for a given Token ID.
   * @dev Throws if `_tokenId` is not a valid NFT.
   * @param _tokenId Id for which we want the issuer.
   * @return Issuer address of _tokenId.
   */
  function issuerOf(uint256 _tokenId) external view returns(address _tokenIssuer){
      require(idToOwner[_tokenId] != address(0), NOT_VALID_NFT);
      _tokenIssuer = certificate[_tokenId].tokenIssuer;
  }

   /**
   * @notice The imprint for a given Token ID.
   * @dev Throws if `_tokenId` is not a valid NFT.
   * @param _tokenId Id for which we want the imprint.
   * @return Imprint address of _tokenId.
   */
  function tokenImprint(uint256 _tokenId) external view returns(bytes32 _imprint){
      require(idToOwner[_tokenId] != address(0), NOT_VALID_NFT);
      _imprint = idToImprint[_tokenId];
  }


  /**
   * @notice The creation date for a given Token ID.
   * @dev Throws if `_tokenId` is not a valid NFT.
   * @param _tokenId Id for which we want the creation date.
   * @return Creation date of _tokenId.
   */
  function tokenCreation(uint256 _tokenId) external view returns(uint256 _tokenCreation){
      require(idToOwner[_tokenId] != address(0), NOT_VALID_NFT);
      _tokenCreation = certificate[_tokenId].tokenCreationDate;
  }

  /**
   * @notice The Token Access for a given Token ID and token type.
   * @dev Throws if `_tokenId` is not a valid NFT.
   * @param _tokenId Id for which we want the token access.
   * @param _tokenType for which we want the token access.
   * @return Token access of _tokenId.
   */
  function tokenHashedAccess(uint256 _tokenId, uint256 _tokenType) external view returns(address _tokenAccess){
      require(idToOwner[_tokenId] != address(0), NOT_VALID_NFT);
      _tokenAccess = tokenAccess[_tokenId][_tokenType];
  }

  /**
   * @notice The recovery timestamp for a given Token ID.
   * @dev Throws if `_tokenId` is not a valid NFT.
   * @param _tokenId Id for which we want the recovery timestamp.
   * @return Recovery timestamp of _tokenId.
   */
  function tokenRecoveryDate(uint256 _tokenId) external view returns(uint256 _tokenRecoveryTimestamp){
      require(idToOwner[_tokenId] != address(0), NOT_VALID_NFT);
      _tokenRecoveryTimestamp = certificate[_tokenId].tokenRecoveryTimestamp;
  }

  /**
   * @notice The recovery timestamp for a given Token ID.
   * @dev Throws if `_tokenId` is not a valid NFT.
   * @param _tokenId Id for which we want the recovery timestamp.
   * @return Recovery timestamp of _tokenId.
   */
  function recoveryRequestOpen(uint256 _tokenId) external view returns(bool _recoveryRequest){
      require(idToOwner[_tokenId] != address(0), NOT_VALID_NFT);
      _recoveryRequest = recoveryRequest[_tokenId];
  }

  /**
   * @notice The rewards for a given Token ID.
   * @param _tokenId Id for which we want the rewards.
   * @return Rewards of _tokenId.
   */
  function getRewards(uint256 _tokenId) external view returns(uint256){
      return rewards[_tokenId];
  }

  /**
   * @notice Check if an operator is valid for a given NFT.
   * @param _tokenId nft to check.
   * @param _operator operator to check.
   * @return true if operator is valid.
   */
  function canOperate(uint256 _tokenId, address _operator) public view returns (bool){
    address tokenOwner = idToOwner[_tokenId];
    return tokenOwner == _operator || ownerToOperators[tokenOwner][_operator];
  }

  /**
   * @notice Change the base URI address.
   * @param _newURIBase the new URI base address.
   */
  function setUriBase(string memory _newURIBase) public onlyOwner(){
      _setUriBase(_newURIBase);
      emit SetNewUriBase(_newURIBase);
  }

  /**
   * @notice Change address of the whitelist.
   * @param _whitelistAddres new address of the whitelist.
   */
  function setWhitelistAddress(address _whitelistAddres) public onlyOwner(){
    arianeeWhitelist = ArianeeWhitelist(address(_whitelistAddres));
    emit SetAddress("whitelistAddress", _whitelistAddres);
  }

  /**
   * @notice Specify information on a reserved NFT.
   * @dev to be called through an authorized contract.
   * @dev Can only be called once and by an NFT's operator.
   * @param _tokenId ID of the NFT to modify.
   * @param _imprint Proof of the certification.
   * @param _uri URI of the JSON certification.
   * @param _initialKey Initial key.
   * @param _tokenRecoveryTimestamp Limit date for the issuer to be able to transfer back the NFT.
   * @param _initialKeyIsRequestKey If true set initial key as request key.
   */
  function hydrateToken(uint256 _tokenId, bytes32 _imprint, string memory _uri, address _initialKey, uint256 _tokenRecoveryTimestamp, bool _initialKeyIsRequestKey, address _owner) public hasAbilities(ABILITY_CREATE_ASSET) whenNotPaused() isOperator(_tokenId, _owner) returns(uint256){
    require(!(certificate[_tokenId].tokenCreationDate > 0), NFT_ALREADY_SET);
    uint256 _tokenCreation = block.timestamp;
    tokenAccess[_tokenId][0] = _initialKey;
    idToImprint[_tokenId] = _imprint;
    idToUri[_tokenId] = _uri;

    arianeeWhitelist.addWhitelistedAddress(_tokenId, _owner);

    if (_initialKeyIsRequestKey) {
      tokenAccess[_tokenId][1] = _initialKey;
    }

    Cert memory _cert = Cert({
             tokenIssuer : _owner,
             tokenCreationDate: _tokenCreation,
             tokenRecoveryTimestamp :_tokenRecoveryTimestamp
            });

    certificate[_tokenId] = _cert;

    emit Hydrated(_tokenId, _imprint, _uri, _initialKey, _tokenRecoveryTimestamp, _initialKeyIsRequestKey, _tokenCreation);

    return rewards[_tokenId];
  }

  /**
   * @notice Check if a token access is valid.
   * @param _tokenId ID of the NFT to validate.
   * @param _hash Hash of tokenId + newOwner address.
   * @param _tokenType Type of token access (0=view, 1=transfer).
   */
  function isTokenValid(uint256 _tokenId, bytes32 _hash, uint256 _tokenType, bytes memory _signature) public view returns (bool){
    return ECDSA.recover(_hash, _signature) ==  tokenAccess[_tokenId][_tokenType];
  }

  /**
   * @notice Legacy function of TransferFrom, add the new owner as whitelisted for the message.
   * @dev Require the store to approve the transfer.
   */
  function _transferFrom(address _to, address _from, uint256 _tokenId) internal {
    require(store.canTransfer(_to, _from, _tokenId));
    super._transferFrom(_to, _from, _tokenId);
    arianeeWhitelist.addWhitelistedAddress(_tokenId, _to);
  }

}