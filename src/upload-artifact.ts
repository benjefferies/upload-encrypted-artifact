import * as core from '@actions/core'

import {UploadOptions, create} from '@actions/artifact'

import {unlinkSync} from 'fs'
import {NoFileOptions} from './constants'
import {encryptFile} from './encrypt'
import {getInputs} from './input-helper'
import {findFilesToUpload} from './search'

async function run(): Promise<void> {
  try {
    const inputs = getInputs()
    const searchResult = await findFilesToUpload(inputs.searchPath)
    if (searchResult.filesToUpload.length === 0) {
      // No files were found, different use cases warrant different types of behavior if nothing is found
      switch (inputs.ifNoFilesFound) {
        case NoFileOptions.warn: {
          core.warning(
            `No files were found with the provided path: ${inputs.searchPath}. No artifacts will be uploaded.`
          )
          break
        }
        case NoFileOptions.error: {
          core.setFailed(
            `No files were found with the provided path: ${inputs.searchPath}. No artifacts will be uploaded.`
          )
          break
        }
        case NoFileOptions.ignore: {
          core.info(
            `No files were found with the provided path: ${inputs.searchPath}. No artifacts will be uploaded.`
          )
          break
        }
      }
    } else {
      const s = searchResult.filesToUpload.length === 1 ? '' : 's'
      core.info(
        `With the provided path, there will be ${searchResult.filesToUpload.length} file${s} uploaded`
      )
      core.debug(`Root artifact directory is ${searchResult.rootDirectory}`)

      if (searchResult.filesToUpload.length > 10000) {
        core.warning(
          `There are over 10,000 files in this artifact, consider creating an archive before upload to improve the upload performance.`
        )
      }

      const filesToUpload: string[] = []
      for (const file of searchResult.filesToUpload) {
        const files = await encryptFile(file, inputs.kmsKeyId)
        filesToUpload.push(...files)
      }

      const artifactClient = create()
      const options: UploadOptions = {
        continueOnError: false
      }
      if (inputs.retentionDays) {
        options.retentionDays = inputs.retentionDays
      }

      const uploadResponse = await artifactClient.uploadArtifact(
        inputs.artifactName,
        filesToUpload,
        searchResult.rootDirectory,
        options
      )

      if (uploadResponse.failedItems.length > 0) {
        core.setFailed(
          `An error was encountered when uploading ${uploadResponse.artifactName}. There were ${uploadResponse.failedItems.length} items that failed to upload.`
        )
      } else {
        core.info(
          `Artifact ${uploadResponse.artifactName} has been successfully uploaded!`
        )
      }

      filesToUpload
        .filter(file => file.endsWith('.key') || file.endsWith('.iv'))
        .forEach(file => {
          // Delete key and iv files
          core.debug(`Deleting ${file}`)
          unlinkSync(file)
        })
    }
  } catch (error) {
    core.setFailed((error as Error).message)
  }
}

run()
