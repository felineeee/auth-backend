import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

// Definite Assignment Assertion (?)
// where do this assign to/from

export class AuthDto {
  @IsEmail({}, { message: 'Invalid email address format' })
  @IsNotEmpty()
  email!: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(6, { message: 'Password must be atleast 6 characters long' })
  password!: string;
}
