import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { Request } from '@nestjs/common';
import { User } from '@prisma/client';
import { JwtGuard } from 'src/auth/guard/jwt.guard';

@Controller('users')
export class UsersController {
  @UseGuards(JwtGuard)
  @Get('me')
  getMe(@Req() req: Request & { user: User }) {
    // TODO code doesnt know req.user
    return req.user;
  }
}
