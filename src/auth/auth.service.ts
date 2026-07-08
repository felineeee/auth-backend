import { ForbiddenException, Injectable } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { AuthDto } from './dto/auth.dto';
import * as otplib from 'otplib';
import * as qrcode from 'qrcode';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}

  async signup(dto: AuthDto) {
    const userExists = await this.usersService.findByEmail(dto.email);
    if (userExists) {
      throw new ForbiddenException('Email already registered');
    }

    const saltRounds = 10;
    const hash = await bcrypt.hash(dto.password, saltRounds);
    const vToken = crypto.randomBytes(32).toString('hex');

    // @TODO create new query for this
    const newUser = await this.usersService.create({
      email: dto.email,
      hash,
      verificationToken: vToken,
      isVerified: false,
    });

    const tokens = await this.getTokens(newUser.id, newUser.email);
    await this.updateRtHash(newUser.id, tokens.refresh_token);

    // return tokens;
    return {
      ...tokens,
      debug_verification_token: vToken,
    };
  }

  async signin(dto: AuthDto) {
    const user = await this.usersService.findByEmail(dto.email);
    if (!user) {
      throw new ForbiddenException('Invalid credentials');
    }

    if (!user.hash) {
      throw new ForbiddenException(
        'This account was created using Google Login. Please sign in via Google.',
      );
    }
    // ERR changes on optional `hash` field, on OAuth login feature
    const passwordMatches = await bcrypt.compare(dto.password, user.hash);
    if (!passwordMatches) {
      throw new ForbiddenException('Invalid credentials');
    }

    if (user.is2faEnabled) {
      return {
        requires2fa: true,
        userId: user.id,
        message: 'Please provide your 2FA authentication code to login.',
      };
    }

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);

    return tokens;
  }

  async logout(userId: number) {
    await this.usersService.update(userId, { hashedRt: null });
  }

  async forgotPassword(email: string) {
    const user = await this.usersService.findByEmail(email);
    if (!user)
      return {
        message: 'If that email exists, a reset link has been generated.',
      };
    const token = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 15 * 20 * 1000);

    await this.usersService.update(user.id, {
      resetToken: token,
      resetTokenExpires: expires,
    });

    return {
      message: 'If that email exists, a reset link has been generated.',
      debug_token: token,
    };
  }

  async resetPassword(token: string, newPassword: string) {
    const user = await this.usersService.findFirst({
      resetToken: token,
      resetTokenExpires: {
        gt: new Date(),
      },
    });

    if (!user) {
      throw new ForbiddenException('Invalid or expired password reset token.');
    }

    const newHash = await bcrypt.hash(newPassword, 10);

    await this.usersService.update(user.id, {
      hash: newHash,
      resetToken: null,
      resetTokenExpires: null,
      hashedRt: null,
    });
    return { message: 'Password has been updated successfully.' };
  }

  async getTokens(userId: number, email: string) {
    const secret = process.env.JWT_SECRET;
    if (!secret) throw new Error('JWT_SECRET missing from environment!');

    const jwtPayload = { sub: userId, email };

    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(jwtPayload, { expiresIn: '15m', secret }),
      this.jwtService.signAsync(jwtPayload, { expiresIn: '7d', secret }),
    ]);

    return {
      access_token: at,
      refresh_token: rt,
    };
  }

  async refreshTokens(userId: number, refreshToken: string) {
    const user = await this.usersService.findById(userId);
    if (!user || !user.hashedRt) throw new ForbiddenException('Access Denied');

    const rtMatches = await bcrypt.compare(refreshToken, user.hashedRt);
    if (!rtMatches) throw new ForbiddenException('Access Denied');

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);
    return tokens;
  }

  async updateRtHash(userId: number, refreshToken: string) {
    // TODO var saltRound
    const hash = await bcrypt.hash(refreshToken, 10);
    await this.usersService.update(userId, { hashedRt: hash });
  }

  async verifyEmail(token: string) {
    const user = await this.usersService.findFirst({
      verificationToken: token,
    });

    if (!user) {
      throw new ForbiddenException('Invalid or expired verification token.');
    }

    await this.usersService.update(user.id, {
      isVerified: true,
      verificationToken: null,
    });

    return {
      message: 'Email verified successfully! Your account is now fully active.',
    };
  }
  async generate2faSecret(userId: number, email: string) {
    const secret = otplib.generateSecret();
    const otpauthUrl = otplib.generateURI({
      issuer: 'MyAuthBackendApp',
      label: email,
      secret: secret,
    });

    await this.usersService.update(userId, { twoFactorSecret: secret });

    const qrCodeDataUrl = await qrcode.toDataURL(otpauthUrl);

    return {
      secret,
      qrCodeDataUrl,
    };
  }
  async verify2faToken(userId: number, token: string) {
    const user = await this.usersService.findById(userId);
    if (!user || !user.twoFactorSecret)
      throw new ForbiddenException('2FA is not set up');

    const isValid = await otplib.verify({
      token,
      secret: user.twoFactorSecret,
    });

    if (!isValid)
      throw new ForbiddenException('Invalid 2FA authentication code');
    return true;
  }
  async enable2fa(userId: number) {
    await this.usersService.update(userId, { is2faEnabled: true });
    return { message: 'Two-factor authentication successfully enabled!' };
  }
}
