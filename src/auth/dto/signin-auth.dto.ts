import { IsString } from 'class-validator';

export class SignInAuthDto {
  @IsString()
  Password: string;

  @IsString()
  Email: string;
}
