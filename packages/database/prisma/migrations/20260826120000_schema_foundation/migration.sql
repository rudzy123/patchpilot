-- CreateSchema
CREATE TABLE "SchemaFoundation" (
    "id" TEXT NOT NULL DEFAULT 'patchpilot-foundation',
    "createdAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SchemaFoundation_pkey" PRIMARY KEY ("id")
);
