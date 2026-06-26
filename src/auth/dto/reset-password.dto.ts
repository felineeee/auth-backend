import { ApiProperty } from '@nestjs/swagger';
import {
  IsEmail,
  IsNotEmpty,
  IsString,
  Length,
  Matches,
  Min,
  MinLength,
} from 'class-validator';

export class ResetPasswordDto {
  @ApiProperty({
    example: 'p_res_xyz789qwe',
    description:
      'The valid password reset token extracted from the user recovery URI link',
  })
  @IsString()
  @IsNotEmpty()
  token: string;

  @ApiProperty({
    example: 'NewSecurePassword123!',
    description:
      'The replacement password string. Must be atleast 8 characters long',
  })
  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  password: string;
}
