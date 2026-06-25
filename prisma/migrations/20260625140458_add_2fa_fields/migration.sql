-- AlterTable
ALTER TABLE "users" ADD COLUMN     "is2faEnabled" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "isVerfied" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "twoFactorSecret" TEXT,
ADD COLUMN     "verificationToken" TEXT,
ALTER COLUMN "hash" DROP NOT NULL;
