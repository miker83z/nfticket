// SPDX-License-Identifier: MIT

pragma solidity ^0.5.0;
pragma experimental ABIEncoderV2;

import "@openzeppelin/contracts/token/ERC721/ERC721Metadata.sol";
import "@openzeppelin/contracts/ownership/Ownable.sol";
import "@openzeppelin/contracts/drafts/Counters.sol";
import "@openzeppelin/contracts/payment/PullPayment.sol";

import "./Verify.sol";

contract OwnableDelegateProxy {}

/**
 * Used to delegate ownership of a contract to another address, to save on unneeded transactions to approve contract use for users
 */
contract ProxyRegistry {
    mapping(address => OwnableDelegateProxy) public proxies;
}

/**
 * @title NFTicket
 * NFTicket - ERC721 contract that whitelists a trading address, and has minting functionality.
 */
contract NFTicket is ERC721Metadata, Ownable, PullPayment {
    using Counters for Counters.Counter;

    Counters.Counter private tokenSupply;
    string private baseTokenURI;

    address public proxyRegistryAddress;
    address public verifyProxy;
    bool public saleIsActive = false;

    // Constant
    uint256 public constant TOTAL_SUPPLY = 512;
    uint256 public constant ticketPrice = 400000000000000; // 0.0004 ETH

    event PermanentURI(string _value, uint256 indexed _id);

    constructor(
        string memory baseURI,
        address proxy,
        address verifyp
    ) public ERC721Metadata("NFTicket", "TIK") {
        baseTokenURI = baseURI;
        proxyRegistryAddress = proxy;
        verifyProxy = verifyp;
    }

    /**
     * @dev Mints a token with id _tokenId to an address _to.
     * @param _to address of the future owner of the token
     * @param _tokenId id of the token minted
     */
    function mintTo(
        address _to,
        uint256 _tokenId,
        Verify.Verfiy_param memory _verify_param
    ) public payable {
        require(
            Verify(verifyProxy).verify(_verify_param),
            "Restriction not verified"
        );
        require(saleIsActive, "Sale must be active to mint");
        require(
            _tokenId > 0 && _tokenId <= TOTAL_SUPPLY,
            "Purchase would exceed max supply"
        );
        require(ticketPrice <= msg.value, "Ether value sent is not correct");

        _safeMint(_to, _tokenId);
        tokenSupply.increment();

        _asyncTransfer(owner(), msg.value);

        emit PermanentURI(baseTokenURI, _tokenId);
    }

    /**
     * @dev Set the base token URI
     */
    function setBaseTokenURI(string memory baseURI) public onlyOwner {
        baseTokenURI = baseURI;
    }

    /**
     * @dev Set the sale state
     */
    function flipSaleState() public onlyOwner {
        saleIsActive = !saleIsActive;
    }

    /**
     * @dev Overridden in order to make it an onlyOwner function
     */
    function withdrawPayments(address payable payee) public onlyOwner {
        super.withdrawPayments(payee);
    }

    function contractURI() public pure returns (string memory) {
        return "https://NFTicket.herokuapp.com/contract/opensea-NFTicket";
    }

    /**
     * @dev Gets the total amount of tokens stored by the contract.
     * @return uint256 representing the total amount of tokens
     */
    function totalSupply() public view returns (uint256) {
        return tokenSupply.current();
    }

    /**
     * Override isApprovedForAll to whitelist user's OpenSea proxy accounts to enable gas-less listings.
     */
    function isApprovedForAll(address owner, address operator)
        public
        view
        returns (bool)
    {
        ProxyRegistry proxyRegistry = ProxyRegistry(proxyRegistryAddress);
        if (address(proxyRegistry.proxies(owner)) == operator) {
            return true;
        }

        return super.isApprovedForAll(owner, operator);
    }

    /**
     * To change the starting tokenId.
     */
    function _startTokenId() internal view returns (uint256) {
        return 1;
    }

    /**
     * @dev Base URI for computing {tokenURI}. If set, the resulting URI for each
     * token will be the concatenation of the `baseURI` and the `tokenId`. Empty
     * by default, can be overriden in child contracts.
     */
    function _baseURI() internal view returns (string memory) {
        return baseTokenURI;
    }
}
