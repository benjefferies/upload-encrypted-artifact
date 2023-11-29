import {GenerateDataKeyCommand, KMSClient} from '@aws-sdk/client-kms'
import {readFileSync, writeFileSync} from 'fs'

import crypto from 'crypto'

const client = new KMSClient()

export async function encryptFile(
  filePath: string,
  kmsKeyId: string
): Promise<[string, string, string]> {
  // Read the file content
  const fileBuffer = readFileSync(filePath)

  try {
    // Encrypt the data
    const command = new GenerateDataKeyCommand({
      KeyId: kmsKeyId,
      NumberOfBytes: 32
    })
    const {CiphertextBlob, Plaintext} = await client.send(command)

    if (!Plaintext || !CiphertextBlob) {
      throw new Error('No encryption key returned from KMS')
    }
    const iv = crypto.randomBytes(16)
    // Use the plaintext encryption key to encrypt the file
    const cipher = crypto.createCipheriv('aes-256-cbc', Plaintext, iv)
    let encrypted = cipher.update(fileBuffer)
    encrypted = Buffer.concat([encrypted, cipher.final()])

    // Overwrite file with encrypted data
    writeFileSync(filePath, encrypted)
    writeFileSync(`${filePath}.key`, CiphertextBlob)
    writeFileSync(`${filePath}.iv`, iv)
    console.log('File encrypted successfully')
    return [filePath, `${filePath}.key`, `${filePath}.iv`]
  } catch (error) {
    console.error('Error encrypting file:', error)
    throw error
  }
}
