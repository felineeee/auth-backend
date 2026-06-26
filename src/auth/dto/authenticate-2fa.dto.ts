import { ApiProperty } from '@nestjs/swagger';
import {
  IsNotEmpty,
  IsNumber,
  IsString,
  Length,
  Matches,
} from 'class-validator';
export class Authenticate2faDto {
  @ApiProperty({
    example: 12,
    description:
      'The temporary database ID of the user attempting to pass the 2FA checkpoint',
  })
  @IsNumber()
  @IsNotEmpty()
  userId!: number;

  @ApiProperty({
    example: '123456',
    description:
      'The 6-digit Time-based One-Time Password (TOTP) token from the user authenticator application',
  })
  @IsString()
  @IsNotEmpty()
  @Length(6, 6, { message: 'The 2FA token code must be exactly 6 digits long' })
  @Matches(/^\d{6}$/, {
    message: 'The 2FA token code must contain numeric characters only',
  })
  code!: string;
}
