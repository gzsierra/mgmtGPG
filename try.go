package main

import (
  "fmt"
  // "time"
  // "os"
  "bytes"
  "encoding/base64"
  "io/ioutil"

  "golang.org/x/crypto/openpgp"
  "golang.org/x/crypto/openpgp/packet"
  _ "golang.org/x/crypto/ripemd160" // XXX
  _ "crypto/sha256"
  // "golang.org/x/crypto/openpgp/armor"

  // "crypto/ecdsa"
)

type gpg struct{
  pub packet.PublicKey
  priv packet.PrivateKey

  entity openpgp.Entity
}

func main()  {

  fmt.Println("TESTING GPG")


  var ent *openpgp.Entity
  var config *packet.Config

  config.Cipher()
  config.Compression()
  // config.DefaultHash =
  config.Hash()
  config.Now()

  ent, err := openpgp.NewEntity("itis", "test", "itis@itis3.com", config)
  if err != nil {
          fmt.Println(err)
          return
  }

  fmt.Println(ent.PrimaryKey, " \n ", ent.PrivateKey)

  encStr := crypt(ent)

  decrypt(ent, encStr)

  // time.Sleep(20)
  // decrypt()

}

func crypt(ent *openpgp.Entity)  (string){
  ents := []*openpgp.Entity{ent}
  fmt.Println("Crypting the test file")

  buf := new(bytes.Buffer)
  w, err := openpgp.Encrypt(buf, ents, ent, nil, nil)

  if err != nil {
        fmt.Println(err)
  }

  _, err = w.Write([]byte("mySecretString"))
  if err != nil {
    fmt.Println(err)
  }

  err = w.Close()
  if err != nil {
      fmt.Println(err)
  }

    // Encode to base64
  bytes, err := ioutil.ReadAll(buf)
  if err != nil {
      fmt.Println(err)
  }
  encStr := base64.StdEncoding.EncodeToString(bytes)
  // Output encrypted/encoded string
  fmt.Println("Encrypted Secret:", encStr)

  return encStr
}

func decrypt(ent *openpgp.Entity, encString string)  {

  // ents := []*openpgp.Entity{ent}
  entityList := openpgp.EntityList{ent}
  fmt.Println("Decrypting the test file")

  // Decode the base64 string
  dec, err := base64.StdEncoding.DecodeString(encString)
  if err != nil {
    fmt.Println(err)
  }

  // Decrypt it with the contents of the private key
  md, err := openpgp.ReadMessage(bytes.NewBuffer(dec), entityList, nil, nil)
  if err != nil {
      fmt.Println(err)
  }
  bytes, err := ioutil.ReadAll(md.UnverifiedBody)
  if err != nil {
      fmt.Println(err)
  }
  fmt.Println(string(bytes))
}
