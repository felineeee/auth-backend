import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class VerifyEmailDto {
  @ApiProperty({
    example: 'v_tok_abc123xyz',
    description: 'The secure cryptographic token sent to the user email inbox',
  })
  @IsString()
  @IsNotEmpty()
  token: string;
}
