import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { use } from 'passport';
import { Strategy, VerifyCallback } from 'passport-google-oauth20';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor() {
    super({
      clientID: process.env.GOOGLE_CLIENT_ID || 'dummy_id',
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || 'dummy_secret',
      callbackURL: 'http://localhost:3000/auth/google/callback,',
      scope: ['email', 'profile'],
    });
  }

  async validate(
    acessToken: string,
    refreshToken: string,
    profile: any,
    done: VerifyCallback,
  ): Promise<any> {
    const { emails } = profile;

    const user = {
      email: emails[0].value,
    };

    done(null, user);
  }
}
