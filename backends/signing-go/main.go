package main

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"strconv"

	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	cryptoTyped "github.com/ethersphere/bee/pkg/crypto"
	eip712 "github.com/ethersphere/bee/pkg/crypto/eip712"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// Endpoint for evm rpc requests
var infura = "https://rinkeby.infura.io/v3/c75f2ce78a4a4b64aa1e9c20316fda3e"
var client, clientConnectErr = ethclient.Dial(infura)

// Simple ERC721 contract with methods to update nft fields and signature verification mechanism
// For this demo use contract in "contracts/GameItem.sol"
var contractAccount = "0x159D0A933137f3EC155f43834BDFCd534A8bfd61"

// Private key should belong to account that deployed contract
var privateKeyString = "a0022ef0d495da2ad7e639f9d93045661f149f31472cedf067a0712b391749df"

// Private key on the server side For GD-3 (use case 8)
var privateKey, _ = crypto.HexToECDSA(privateKeyString)

// user's address associated with the hero id
var clientAddress = common.HexToAddress("0x24d13b65bAbFc38f6eCA86D9e73C539a1e0C0196")

type Item struct {
	itemType int `json:"itemType"`
	strength int `json:"strength"`
	level    int `json:"level"`
}

type ItemInfo struct {
	TokenId    int64  `json:"tokenId"`
	ItemType   int64  `json:"itemType"`
	Strength   int64  `json:"strength"`
	Level      int64  `json:"level"`
	ExpireTime int64  `json:"expireTime"`
	Signature  []byte `json:"signature"`
}

type Payload struct {
	hero      ItemInfo `json:"hero"`
	signature string   `json:"signature"`
}

type SignatureCheckInput struct {
	Signature string `json:"signature"`
	Message   string `json:"message"`
}

type SignatureCheckOutput struct {
	Address string `json:"address"`
}

func main() {
	r := setupRouter()
	// Listen and Server in 0.0.0.0:8080
	r.Run(":8080")
}

func setupRouter() *gin.Engine {
	// Disable Console Color
	// gin.DisableConsoleColor()
	r := gin.Default()

	r.Use(cors.Default())

	// GD-3: Fetch the hero data based on its ID and return the transaction to be signed.
	r.GET("/hero/:id", func(c *gin.Context) {
		// in this example, we don't have backend database, the desired actions should be
		// 1) check if the id exists in db
		// 2) fetch the clientAddress associate with this id
		// 3) prepare the transaction to be signed by the users to update the properties of NFT heros.
		idParam := c.Params.ByName("id")

		if clientConnectErr != nil {
			log.Fatal(clientConnectErr)
		}

		id, _ := strconv.ParseInt(idParam, 10, 64)

		hero := &ItemInfo{
			TokenId:    id,
			ItemType:   1,
			Strength:   10,
			Level:      15,
			ExpireTime: 1642739319576,
		}

		hero.Signature = generateSignature(*hero)

		payloadStr, err := json.Marshal(hero)
		if err == nil {
			c.Data(http.StatusOK, gin.MIMEJSON, payloadStr)
		}
	})

	// GD-2: Verify message and signature, if passed, bind this address to user's table
	// Input: message and signature
	// Output: Users' address
	r.POST("/account/verification/address", func(c *gin.Context) {
		var input SignatureCheckInput
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		data := []byte(input.Message)

		// Verify the Signature and message, if passed, return pub key
		sigPublicKey := getAddrFromSign(input.Signature, data)
		// Convert pub key to address
		address := string(sigPublicKey)

		// add address to a database
		output := &SignatureCheckOutput{Address: address}

		// return address
		payloadStr, err := json.Marshal(output)
		if err == nil {
			c.Data(http.StatusOK, gin.MIMEJSON, payloadStr)
		}
	})

	return r
}

func signatureToHex(r *big.Int, s *big.Int, v *big.Int) string {
	return "0x" + hex.EncodeToString(r.Bytes()) + hex.EncodeToString(s.Bytes()) + hex.EncodeToString(v.Bytes())
}

func getAddrFromSign(sigHex string, msg []byte) string {
	sig := hexutil.MustDecode(sigHex)
	if sig[64] != 27 && sig[64] != 28 {
		log.Fatal("Problem 1")
	}
	sig[64] -= 27

	pubKey, err := crypto.SigToPub(signHash(msg), sig)
	if err != nil {
		log.Fatal(err)
	}

	recoveredAddr := crypto.PubkeyToAddress(*pubKey)

	return recoveredAddr.String()
}

func signHash(data []byte) []byte {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	return crypto.Keccak256([]byte(msg))
}

func generateSignature(itemInfo ItemInfo) []byte {
	pData, err := hex.DecodeString(privateKeyString)
	if err != nil {
		log.Fatal(err)
	}

	privKey, err := cryptoTyped.DecodeSecp256k1PrivateKey(pData)
	if err != nil {
		log.Fatal(err)
	}

	signer := cryptoTyped.NewDefaultSigner(privKey)

	var EIP712DomainType = []eip712.Type{
		{
			Name: "name",
			Type: "string",
		},
		{
			Name: "version",
			Type: "string",
		},
		{
			Name: "chainId",
			Type: "uint256",
		},
		{
			Name: "verifyingContract",
			Type: "address",
		},
	}

	var EIP712Types = []eip712.Type{
		{
			Name: "tokenId",
			Type: "uint256",
		},
		{
			Name: "itemType",
			Type: "uint256",
		},
		{
			Name: "strength",
			Type: "uint256",
		},
		{
			Name: "level",
			Type: "uint256",
		},
		{
			Name: "expireTime",
			Type: "uint256",
		},
	}

	var typeData = eip712.TypedData{
		Domain: eip712.TypedDataDomain{
			Name:              "GameItem",
			Version:           "1",
			ChainId:           math.NewHexOrDecimal256(4), // this should be changed for contract
			VerifyingContract: contractAccount,            // this should be changed for contract
		},
		Types: eip712.Types{
			"EIP712Domain": EIP712DomainType,
			"ItemInfo":     EIP712Types,
		},
		PrimaryType: "ItemInfo",
		Message: eip712.TypedDataMessage{
			"tokenId":    math.NewHexOrDecimal256(itemInfo.TokenId),
			"itemType":   math.NewHexOrDecimal256(itemInfo.ItemType),
			"strength":   math.NewHexOrDecimal256(itemInfo.Strength),
			"level":      math.NewHexOrDecimal256(itemInfo.Level),
			"expireTime": math.NewHexOrDecimal256(itemInfo.ExpireTime),
		},
	}

	var signature, err2 = signer.SignTypedData(&typeData)
	if err2 != nil {
		log.Fatalf("SignTypedData error %v", err2)
	}
	return signature
}
