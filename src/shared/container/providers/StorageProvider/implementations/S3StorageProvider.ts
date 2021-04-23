import { S3 } from "aws-sdk";
import fs from "fs";
import mime from "mime";
import { resolve } from "path";

import upload from "@config/upload";

import { IStorageProvider } from "../IStorageProvider";

class S3StorageProvider implements IStorageProvider {
  private client: S3;

  constructor() {
    // s3 instance
    this.client = new S3({
      region: process.env.AWS_BUCKET_REGION,
    });
  }

  async save(file: string, folder: string): Promise<string> {
    // get the file in the temporary folder
    const originalname = resolve(upload.tmpFolder, file);

    const fileContent = await fs.promises.readFile(originalname);

    const ContentType = mime.getType(originalname);

    // create an Objet in s3 bucket | saves the file
    await this.client
      .putObject({
        Bucket: `${process.env.AWS_BUCKET}/${folder}`,
        Key: file,
        ACL: "public-read",
        Body: fileContent,
        ContentType,
      })
      .promise();

    // deletes the file from the temporary folder
    await fs.promises.unlink(originalname);

    return file;
  }

  async delete(file: string, folder: string): Promise<void> {
    // deletes an Object in s3 bucket | deletes the file
    await this.client
      .deleteObject({
        Bucket: `${process.env.AWS_BUCKET}/${folder}`,
        Key: file,
      })
      .promise();
  }
}

export { S3StorageProvider };
