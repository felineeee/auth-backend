import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from './../src/app.module';
import { PrismaService } from 'src/prisma.service';
import * as dotenv from 'dotenv';
dotenv.config();
import cookieParser from 'cookie-parser';

describe('Authentication Gateway (E2E)', () => {
  let app: INestApplication;
  let prisma: PrismaService;

  const testUser = {
    email: 'developer@example.com',
    password: 'SecurePassword2026!',
    newPassword: 'MoreSecurePassword2026!',
  };

  let savedVerificationToken: string;
  let savedResetToken: string;
  let savedUserId: number;
  let authCookies: string[] = [];

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.use(cookieParser());

    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        transform: true,
      }),
    );

    await app.init();

    prisma = moduleFixture.get<PrismaService>(PrismaService);
    await prisma.user.deleteMany({ where: { email: testUser.email } });
  });

  afterAll(async () => {
    await prisma.user.deleteMany({ where: { email: testUser.email } });
    await prisma.$disconnect();
    await app.close();
  });

  // REGISTRATION
  describe('POST /auth/signup', () => {
    it('should block registration if payload fields break DTO limits', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/signup')
        .send({ email: 'malformed-email', password: '123' })
        .expect(400);
      expect(res.body.message).toContain('Invalid email address format');
    });

    it('should successfully register a valid user, issue cookies, and generate an inactive state', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/signup')
        .send({ email: testUser.email, password: testUser.password })
        .expect(201);

      expect(res.body.message).toEqual('Account registered successfully');
      expect(res.header['set-cookie']).toBeDefined();

      const dbUser = await prisma.user.findUnique({
        where: { email: testUser.email },
      });
      expect(dbUser).toBeTruthy();
      expect(dbUser!.isVerified).toBe(false);
      savedVerificationToken = dbUser!.verificationToken!;
      savedUserId = dbUser!.id;
    });

    it('should block duplicate email signups to prevent account overrides', async () => {
      await request(app.getHttpServer())
        .post('/auth/signup')
        .send({ email: testUser.email, password: testUser.password })
        .expect(403);
    });
  });

  // EMAIL VERIFICATION
  describe('POST /auth/verify-email', () => {
    it('should block verification attempts containing empty string inputs', async () => {
      await request(app.getHttpServer())
        .post('/auth/verify-email')
        .send({ token: '' })
        .expect(400);
    });

    it('should block verification attempts containing empty string inputs', async () => {
      await request(app.getHttpServer())
        .post('/auth/verify-email')
        .send({ token: savedVerificationToken })
        .expect(201);

      const dbUser = await prisma.user.findUnique({
        where: { email: testUser.email },
      });
      expect(dbUser!.isVerified).toBe(true);
      expect(dbUser!.verificationToken).toBeNull();
    });
  });

  // AUTHENTICATION AND SESSION
  describe('POST /auth/signin', () => {
    it('should reject signin attempts using incorrect passwords', async () => {
      await request(app.getHttpServer())
        .post('/auth/signin')
        .send({ email: testUser.email, password: 'WrongPassword!' })
        .expect(403);
    });

    it('should authenticate a verified user and accurately capture session cookies', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/signin')
        .send({ email: testUser.email, password: testUser.password })
        .expect(200);

      expect(res.body.message).toEqual('Logged in successfully');
      expect(res.headers['set-cookie']).toBeDefined();

      const cookieHeader = res.headers['set-cookie'];
      authCookies = cookieHeader ? [cookieHeader].flat() : [];
    });
  });

  describe('POST /auth/refresh', () => {
    it('should block token rotation if no cookies are supplied', async () => {
      await request(app.getHttpServer()).post('/auth/refresh').expect(403);
    });
    it('should reissue a clean cookie pair when presented with a valid refresh token cookie', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/refresh')
        .set('Cookie', authCookies.join('; '))
        .expect(200);

      expect(res.body.message).toEqual('Tokens refreshed successfully');
      expect(res.headers['set-cookie']).toBeDefined();

      const cookieHeader = res.headers['set-cookie'];
      authCookies = cookieHeader ? [cookieHeader].flat() : [];
    });
  });

  // PASSWORD RECOVERY PHASE
  describe('Password Recovery Lifecycle', () => {
    it('should generate a cryptographic reset token inside the DB upon reset', async () => {
      await request(app.getHttpServer())
        .post('/auth/forgot-password')
        .send({ email: testUser.email })
        .expect(201);

      const dbUser = await prisma.user.findUnique({
        where: { email: testUser.email },
      });
      expect(dbUser!.resetToken).toBeTruthy();
      expect(dbUser!.resetTokenExpires).toBeGreaterThan(new Date().getTime());
      savedResetToken = dbUser!.resetToken!;
    });
    it('should block password replacement payloads breaking DTO size limitations', async () => {
      await request(app.getHttpServer())
        .post('/auth/reset-password')
        .send({ token: savedResetToken, password: 'short' })
        .expect(400);
    });
    it('should consume the token, alter the hash, and wipe out active recovery timestamps', async () => {
      await request(app.getHttpServer())
        .post('/auth/reset-password')
        .send({ token: savedResetToken, password: testUser.newPassword })
        .expect(201);

      const dbUser = await prisma.user.findUnique({
        where: { email: testUser.email },
      });
      expect(dbUser!.resetToken).toBeNull();
      expect(dbUser!.resetTokenExpires).toBeNull();

      testUser.password = testUser.newPassword;
    });
  });

  // TWO-FACTOR AUTHENTICATION (2FA)
  describe('Two-Factor Authentication', () => {
    it('should deny access to 2FA generation tools if user lacks active JWT guards', async () => {
      await request(app.getHttpServer()).post('/auth/2fa/generate').expect(401);
    });
    it('should return a valid base64 or otpauth configuration string when authenticated', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/2fa/generate')
        .set('Cookie', authCookies)
        .expect(201);

      expect(res.body).toHaveProperty('qrCodeUrl');
      const dbUser = await prisma.user.findUnique({
        where: { email: testUser.email },
      });
      expect(dbUser!.twoFactorSecret).toBeTruthy();
    });

    it('should block activation attempts if the 2FA format breaks digit limits', async () => {
      await request(app.getHttpServer())
        .post('/auth/2fa/turn-on')
        .set('Cookie', authCookies)
        .send({ code: 'abd' })
        .expect(400);
    });

    it('should block dynamic authorization checking if DTO parameters are incomplete', async () => {
      await request(app.getHttpServer())
        .post('/auth/2fa/authenticate')
        .send({ userId: savedUserId, code: '123' })
        .expect(400);
    });
  });

  // LOGOUT
  describe('POST /auth/logout', () => {
    it('should successfully strip credentials from active DB sessions and clear client headers', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/logout')
        .set('Cookie', authCookies)
        .expect(200);

      expect(res.body.message).toEqual('Logged out successfully');

      const cookiesHeader = JSON.stringify(res.headers['set-cookies']);
      expect(cookiesHeader).toContain('access_token=;');
      expect(cookiesHeader).toContain('refresh_token=;');

      const dbUser = await prisma.user.findUnique({
        where: { email: testUser.email },
      });
      expect(dbUser!.hashedRt).toBeNull();
    });
  });
});
