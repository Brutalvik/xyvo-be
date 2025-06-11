// services/sellerProfileService.mjs
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  PutCommand,
  GetCommand,
} from "@aws-sdk/lib-dynamodb";

export class SellerProfileService {
  constructor(region, tableName) {
    const client = new DynamoDBClient({ region });
    this.docClient = DynamoDBDocumentClient.from(client);
    this.tableName = tableName;
  }

  async createSellerProfile(profile) {
    const command = new PutCommand({
      TableName: this.tableName,
      Item: profile,
      ConditionExpression: "attribute_not_exists(sellerId)",
    });
    await this.docClient.send(command);
    return profile;
  }

  async getSellerProfile(sellerId) {
    const command = new GetCommand({
      TableName: this.tableName,
      Key: { sellerId },
    });
    const { Item } = await this.docClient.send(command);
    return Item;
  }
}
