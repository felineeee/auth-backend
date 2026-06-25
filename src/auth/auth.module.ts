import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UsersModule } from 'src/users/users.module';
import { JwtStrategy } from './strategy/jwt.strategy';
import { GoogleStrategy } from './strategy/google.strategy';

@Module({
  imports: [UsersModule, JwtModule.register({})],
  providers: [AuthService],
  controllers: [AuthController, JwtStrategy, GoogleStrategy],
})
export class AuthModule {}
