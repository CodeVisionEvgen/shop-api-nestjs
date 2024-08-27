import { IsOptional, IsString, Length } from 'class-validator';

export class SignUpAuthDto {
  @Length(2, 20)
  @IsString()
  FirstName: string;

  @Length(2, 20)
  @IsOptional()
  @IsString()
  LastName: string;

  @Length(8, 20)
  @IsString()
  Password: string;

  @Length(1, 30)
  @IsOptional()
  @IsString()
  Email: string;
}
