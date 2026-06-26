import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty } from 'class-validator';

export class ForgotPasswordDto {
  @ApiProperty({
    example: 'developer@example.com',
    description:
      'The registered email address requesting a password recovery link',
  })
  @IsEmail()
  @IsNotEmpty()
  email!: string;
}
