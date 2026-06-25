import { ForbiddenException, Injectable } from '@nestjs/common';
import { UsersService } from 'src/users/users.service';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma.service';
import * as bcrypt from 'bcrypt';
import { AuthDto } from './auth.dto';
import { access } from 'fs';

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
    const newUser = await this.usersService.create(dto.email, hash);

    const tokens = await this.getTokens(newUser.id, newUser.email);

    await this.updateRtHash(newUser.id, tokens.refresh_token);
    return tokens;
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
}
