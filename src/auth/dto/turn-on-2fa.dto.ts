import { IsNotEmpty, IsString, Length, Matches } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class TurnOn2faDto {
  @ApiProperty({
    example: '123456',
    description:
      'The 6-digit Time-based One-Time Password (TOTP) code from your authenticator app',
  })
  @IsString()
  @IsNotEmpty()
  @Length(6, 6, { message: 'The 2FA code must be exactly 6 digits long' })
  @Matches(/^\d{6}$/, {
    message: 'The 2FA code must contain numeric characters only',
  })
  code!: string;
}
