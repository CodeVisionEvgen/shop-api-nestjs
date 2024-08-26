import {
  Controller,
  Post,
  Body,
  UnauthorizedException,
  Res,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignUpAuthDto } from './dto/signup-auth.dto';
import { User } from 'src/user/entities/user.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { Response } from 'express';
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    @InjectRepository(User) private userRepo: Repository<User>,
  ) {}

  @Post('signup')
  async signupByJWT(
    @Body() createAuthDto: SignUpAuthDto,
    @Res() res: Response,
  ) {
    const findUser = await this.userRepo.findOneBy({
      Email: createAuthDto.Email,
    });

    if (findUser) throw new UnauthorizedException('User exists');

    const passwd = createAuthDto.Password;
    const encryptedPasswd = await bcrypt.hash(passwd, 13);

    const user = await this.authService.createUserJWT({
      ...createAuthDto,
      Password: encryptedPasswd,
    });

    const [AccessToken, RefreshToken] =
      await this.authService.generateTokens(user);

    res.cookie('RefreshToken', RefreshToken);
    res.cookie('AccessToken', AccessToken);
    res.json({
      ok: 1,
    });
  }
}
