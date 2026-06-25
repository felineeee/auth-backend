import { ForbiddenException, Injectable } from '@nestjs/common';
import { UsersService } from 'src/users/users.service';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma.service';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { AuthDto } from './auth.dto';
import { access } from 'fs';
import { debug } from 'console';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private prisma: PrismaService,
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
    const newUser = await this.prisma.user.create({
      data: {
        email: dto.email,
        hash,
        verificationToken: vToken,
        isVerified: false,
      },
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

    const passwordMatches = await bcrypt.compare(dto.password, user.hash);
    if (!passwordMatches) {
      throw new ForbiddenException('Invalid credentials');
    }

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);

    return tokens;
  }

  async logout(userId: number) {
    await this.prisma.user.update({
      where: { id: userId },
      data: { hashedRt: null },
    });
  }

  async forgotPassword(email: string) {
    const user = await this.usersService.findByEmail(email);
    if (!user)
      return {
        message: 'If that email exists, a reset link has been generated.',
      };
    const token = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 15 * 20 * 1000);

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        resetToken: token,
        resetTokenExpired: expires,
      },
    });

    return {
      message: 'If that email exists, a reset link has been generated.',
      debug_token: token,
    };
  }

  async resetPassword(token: string, newPassword: string) {
    const user = await this.prisma.user.findFirst({
      where: {
        resetToken: token,
        resetTokenExpires: {
          gt: new Date(), //Mistake on fields type on schema.prisma
        },
      },
    });

    if (!user) {
      throw new ForbiddenException('Invalid or expired password reset token.');
    }

    const newHash = await bcrypt.hash(newPassword, 10);

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        hash: newHash,
        resetToken: null,
        resetTokenExpires: null,
        hashedRt: null,
      },
    });

    return { message: 'Password has been updated successfully.' };
  }

  private async signToken(
    userId: number,
    email: string,
  ): Promise<{ access_token: string }> {
    const secret = process.env.JWT_SECRET;
    if (!secret) {
      throw new Error(
        'FATAL CONFIGURATION ERROR: JWT_SECRET environment variable is not defined!',
      );
    }
    const payload = { sub: userId, email };
    const token = await this.jwtService.signAsync(payload, {
      expiresIn: '15m',
      secret: secret,
    });

    return { access_token: token };
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
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });
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
    await this.prisma.user.update({
      where: { id: userId },
      data: { hashedRt: hash },
    });
  }

  async verifyEmail(token: string) {
    const user = await this.prisma.user.findFirst({
      where: { verificationToken: token },
    });

    if (!user) {
      throw new ForbiddenException('Invalid or expired verification token.');
    }

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        isVerfied: true,
        verificationToken: null,
      },
    });

    return {
      message: 'Email verified successfully! Your account is now fully active.',
    };
  }
}
