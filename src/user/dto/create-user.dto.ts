import { IsOptional, IsString } from 'class-validator';

export class CreateUserDto {
  @IsString()
  nickName: string;

  @IsOptional()
  @IsString()
  firstName: string;

  @IsOptional()
  @IsString()
  lastName: string;

  @IsString()
  password: string;

  @IsOptional()
  @IsString()
  email: string;
}
