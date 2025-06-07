import fastifyMultipart from "@fastify/multipart";
import { v4 as uuid } from "uuid";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";

const region = process.env.AWS_REGION;
const bucket = process.env.AWS_BUCKET_NAME;
const s3 = new S3Client({ region });

/**
 * Registers the /seller/products route
 * @param {import('fastify').FastifyInstance} app
 */
export async function sellerProductsRoutes(app) {
  app.register(fastifyMultipart);

  // ✅ CORS Preflight Handler
  app.options("/seller/products", async (req, reply) => {
    reply
      .header("Access-Control-Allow-Origin", req.headers.origin || "*")
      .header("Access-Control-Allow-Methods", "POST, OPTIONS")
      .header("Access-Control-Allow-Headers", "Content-Type, Authorization")
      .header("Access-Control-Allow-Credentials", "true")
      .code(204)
      .send();
  });

  // ✅ POST Route to Add Seller Product
  app.post("/seller/products", async (req, reply) => {
    try {
      const parts = req.parts();
      const product = {
        title: "",
        description: "",
        price: "",
        quantity: "",
        category: "",
        tags: "",
        isActive: true,
        images: [],
        sellerId: req.user?.sub || "mock-seller-id", // Replace with real auth logic
      };

      for await (const part of parts) {
        if (part.file) {
          const key = `products/${uuid()}-${part.filename}`;
          await s3.send(
            new PutObjectCommand({
              Bucket: bucket,
              Key: key,
              Body: part.file,
              ContentType: part.mimetype,
            })
          );
          product.images.push(`https://${bucket}.s3.amazonaws.com/${key}`);
        } else {
          const field = part.fieldname;
          const value = part.value;
          if (field in product) product[field] = value;
        }
      }

      req.log.info("Product submitted by seller:", product);

      // TODO: Save product to database here

      reply
        .header("Access-Control-Allow-Origin", req.headers.origin || "*")
        .header("Access-Control-Allow-Credentials", "true")
        .status(201)
        .send({ message: "Product created", product });
    } catch (err) {
      req.log.error("Product creation error:", err);
      reply.status(500).send({ error: "Failed to process product submission" });
    }
  });
}
