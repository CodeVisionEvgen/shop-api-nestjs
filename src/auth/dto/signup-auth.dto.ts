import { IsOptional, IsString } from 'class-validator';

export class SignUpAuthDto {
  @IsString()
  FirstName: string;

  @IsOptional()
  @IsString()
  LastName: string;

  @IsString()
  Password: string;

  @IsOptional()
  @IsString()
  Email: string;
}
