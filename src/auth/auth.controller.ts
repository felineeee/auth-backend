import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Get,
  Res,
  Req,
  UseGuards,
  ForbiddenException,
} from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';
import { type Response, type Request } from 'express';
import { JwtService } from '@nestjs/jwt';
import { AuthService } from './auth.service';
import { AuthDto } from './auth.dto';
import { JwtGuard } from './guard/jwt.guard';
import { PassThrough } from 'stream';
import { ref } from 'process';
import passport, { use } from 'passport';
import { AuthGuard } from '@nestjs/passport';
import { PrismaService } from 'src/prisma.service';
import { BADFAMILY } from 'dns';
import { UsersService } from 'src/users/users.service';

@Controller('auth')
@UseGuards(ThrottlerGuard)
export class AuthController {
  constructor(
    private authService: AuthService,
    private userService: UsersService,
    private jwtService: JwtService,
    private prisma: PrismaService,
  ) {}

  private setCookies(
    res: Response,
    tokens: { access_token: string; refresh_token: string },
  ) {
    res.cookie('access_token', tokens.access_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 15 * 60 * 1000,
    });

    res.cookie('refresh_token', tokens.refresh_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
  }

  @Post('signup')
  async signup(
    @Body() dto: AuthDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.signup(dto);
    this.setCookies(res, result);

    return { message: 'Account registered sucessfully' };
  }

  @HttpCode(HttpStatus.OK)
  @Post('signin')
  async signin(
    @Body() dto: AuthDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.signin(dto);
    if ('requires2fa' in result) {
      return result;
    }
    this.setCookies(res, result);

    return { message: 'Logged in successfully' };
  }

  @UseGuards(JwtGuard)
  @HttpCode(HttpStatus.OK)
  @Post('logout')
  async logout(@Req() req: any, @Res({ passthrough: true }) res: Response) {
    await this.authService.logout(req.user.id);

    res.clearCookie('access_token');
    res.clearCookie('refresh_token');

    return { message: 'Logged out successfully' };
  }

  @Post('forgot-password')
  async forgotPassword(@Body('email') email: string) {
    return this.authService.forgotPassword(email);
  }

  @Post('reset-password')
  async resetPassword(
    @Body('token') token: string,
    @Body('newPassword') newPassword: string,
  ) {
    return this.authService.resetPassword(token, newPassword);
  }

  @HttpCode(HttpStatus.OK)
  @Post('refresh')
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const refreshToken = req.cookies?.['refresh_token'];
    if (!refreshToken) throw new ForbiddenException('Access Denied');

    try {
      const payload = await this.jwtService.verifyAsync(refreshToken, {
        secret: process.env.JWT_SECRET,
      });
      const tokens = await this.authService.refreshTokens(
        payload.sub,
        refreshToken,
      );
      this.setCookies(res, tokens);

      return { message: 'Tokens refreshed successfully' };
    } catch (error) {
      throw new ForbiddenException('Access Denied');
    }
  }

  @Post('verify-email')
  async verifyEmail(@Body('token') token: string) {
    return this.authService.verifyEmail(token);
  }

  @Get('google')
  @UseGuards(AuthGuard('google'))
  async googleAuth(@Req() req: Request) {}

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  async googleAuthRedirect(
    @Req() req: any,
    @Res({ passthrough: true }) res: Response,
  ) {
    const email = req.user.email;
    let user = await this.userService.findByEmail(email);
    if (!user) {
      user = await this.userService.create({
        email,
        isVerified: true,
      });
    }

    const tokens = await this.authService.getTokens(user.id, user.email);
    await this.authService.updateRtHash(user.id, tokens.refresh_token);
    this.setCookies(res, tokens);

    return { message: 'Logged in via Google successfully!' };
  }

  @UseGuards(JwtGuard)
  @Post('2fa/generate')
  async generate2fa(@Req() req: any) {
    return this.authService.generate2faSecret(req.user.id, req.user.email);
  }

  @UseGuards(JwtGuard)
  @Post('2fa/turn-on')
  async turnOn2fa(@Req() req: any, @Body('code') code: string) {
    await this.authService.verify2faToken(req.user.id, code);
    return this.authService.enable2fa(req.user.id);
  }

  @Post('2fa/authenticate')
  async authenticate2fa(
    @Body('userId') userId: number,
    @Body('code') code: string,
    @Res({ passthrough: true }) res: Response,
  ) {
    await this.authService.verify2faToken(userId, code);

    const user = await this.userService.findById(userId);
    if (!user) throw new ForbiddenException('Access denied');

    const token = await this.authService.getTokens(user.id, user.email);
    await this.authService.updateRtHash(user.id, token.refresh_token);
    return { message: 'Logged in successfully with 2FA' };
  }
}
