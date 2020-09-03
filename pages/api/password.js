// Next.js API route support: https://nextjs.org/docs/api-routes/introduction

import CryptoJS from 'crypto-js'

export default (req, res) => {
  res.statusCode = 200

  if (req.method === 'POST') {
    const { secretKey, password } = JSON.parse(req.body)

    const hashedSecrentKey = CryptoJS.SHA256(secretKey).toString()
    const generatedPassword = CryptoJS.SHA3(CryptoJS.HmacSHA256(password, hashedSecrentKey).toString()).toString(CryptoJS.enc.Base64)

    res.json({ generatedPassword })
  } else {
    res.json({ error: 'no method allowed'})
  }
}