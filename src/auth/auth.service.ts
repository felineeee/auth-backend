import { ForbiddenException, Injectable } from '@nestjs/common';
import { UsersService } from 'src/users/users.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { AuthDto } from './auth.dto';

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

    const newUser = await this.usersService.create(dto.email, hash);
    return this.signToken(newUser.id, newUser.email);
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

    return this.signToken(user.id, user.email);
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
}
