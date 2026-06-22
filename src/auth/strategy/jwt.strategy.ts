import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { Request } from 'express';
import { UsersService } from 'src/users/users.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(private usersService: UsersService) {
    const secret = process.env.JWT_SECRET;
    if (!secret) {
      throw new Error(
        'FATAL CONFIGURATION ERROR: JWT_SECRET environment variable is not defined!',
      );
    }

    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (req: Request) => {
          let token = null;
          if (req && req.cookies) {
            token = req.cookies['access_token'];
          }
          return token;
        },
      ]),
      secretOrKey:
        // TODO this part of code is warn if .env fails to load. this part need guarantee that it needs to be defined
        // process.env.JWT_SECRET || 'fallback_secret_key_dont_use_in_production',
        secret,
    });
  }

  async validate(payload: { sub: number; email: string }) {
    const user = await this.usersService.findByEmail(payload.email);
    if (!user) {
      throw new UnauthorizedException('User no longer exists');
    }
    const { hash, ...userWithoutHash } = user;
    // TODO need implication of deleting user.hash, whether its safe or not
    // delete user.hash;
    return userWithoutHash;
  }
}
