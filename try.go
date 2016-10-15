package main

import (
  "fmt"
  "bytes"
  "encoding/base64"
  "io/ioutil"

  "crypto"
  "golang.org/x/crypto/openpgp"
  "golang.org/x/crypto/openpgp/packet"
)

func main()  {

  fmt.Println("TESTING GPG")

  var ent *openpgp.Entity
  var config packet.Config
  config.DefaultHash = crypto.SHA256

  ent, err := openpgp.NewEntity("itis", "test", "itis@itis3.com", &config)
  if err != nil {
          fmt.Println(err)
          return
  }

  fmt.Println(ent.PrimaryKey, " \n ", ent.PrivateKey)
  encStr := crypt(ent)
  decrypt(ent, encStr)
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
