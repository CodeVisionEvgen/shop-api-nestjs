import { Controller, Post, Body, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignUpAuthDto } from './dto/signup-auth.dto';
import { User } from 'src/user/entities/user.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    @InjectRepository(User) private userRepo: Repository<User>,
  ) {}

  @Post('signup')
  async signupByJWT(@Body() createAuthDto: SignUpAuthDto) {
    const findUser = await this.userRepo.findOneBy({
      Email: createAuthDto.Email,
    });

    if (findUser) throw new UnauthorizedException('User exists');

    const passwd = createAuthDto.Password;
    const encryptedPasswd = await bcrypt.hash(passwd, 13);

    return this.authService.createUserJWT({
      ...createAuthDto,
      Password: encryptedPasswd,
    });
  }
}
