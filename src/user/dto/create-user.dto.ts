import { IsOptional, IsString } from 'class-validator';

export class CreateUserDto {
  @IsString()
  FirstName: string;

  @IsOptional()
  @IsString()
  LastName?: string;

  @IsString()
  Password: string;

  @IsString()
  Email: string;
}
