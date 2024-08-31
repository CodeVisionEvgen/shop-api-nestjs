import {
  Controller,
  Post,
  Body,
  UnauthorizedException,
  Res,
  // Get,
  UseGuards,
  HttpCode,
  Get,
  Req,
  Param,
  BadRequestException,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignUpAuthDto } from './dto/signup-auth.dto';
import { User } from '../../src/user/entities/user.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { Request, Response } from 'express';
import { SignInAuthDto } from './dto/signin-auth.dto';
import { JwtAuth } from './entities/jwt-auth.entity';
import { RefreshTokenGuard } from '../../guards/refreshToken.guard';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { MailerService } from '@nestjs-modules/mailer';
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    @InjectRepository(User) private userRepo: Repository<User>,
    @InjectRepository(JwtAuth) private jwtAuthRepo: Repository<JwtAuth>,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly mailerService: MailerService,
  ) {}

  @Get('email/confirm/:uuid')
  async confirmEmail(
    @Param('uuid') uuid: string,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    const findedUUID = await this.authService.findCallbackUUID(uuid);

    if (!findedUUID) throw new BadRequestException('UUID IS NOT VALID');

    const user = await this.authService.signupUserJwt(uuid);
    const [AccessToken, RefreshToken] =
      await this.authService.generateTokens(user);

    const { headers } = req;

    const userAgent = headers['user-agent'];

    await this.jwtAuthRepo.save({
      Sub: user.Id,
      Access: AccessToken,
      Refresh: RefreshToken,
      UserAgent: userAgent,
    });
    this.setAuthCookies(res, RefreshToken, AccessToken);
    res.json({
      ok: 1,
    });
  }

  @Post('signup')
  async signupByJWT(
    @Body() signUpAuthDto: SignUpAuthDto,
    @Res() res: Response,
  ) {
    const findUser = await this.userRepo.findOneBy({
      Email: signUpAuthDto.Email,
    });

    if (findUser) throw new UnauthorizedException('User exists');

    const callBackUUID =
      [...signUpAuthDto.Email]
        .sort()
        .map((letter) => Buffer.from(letter).toString('hex'))
        .join('') + Math.floor(Math.random() * 44);

    await this.mailerService.sendMail({
      to: signUpAuthDto.Email,
      subject: 'Welcome',
      template: './auth/email-verification.template.pug',
      context: {
        name: signUpAuthDto.FirstName,
        callBackURL: `${this.configService.get('DOMAIN_PROTOCOL')}://${this.configService.get('DOMAIN_URL')}:${this.configService.get('DOMAIN_PORT')}/api/auth/email/confirm/${callBackUUID}`,
      },
    });

    const passwd = signUpAuthDto.Password;

    const encryptedPasswd = await bcrypt.hash(passwd, 13);

    await this.authService.createEmailUserValidationJWT({
      ...signUpAuthDto,
      Password: encryptedPasswd,
      CallBackUUID: callBackUUID,
    });

    res.json({
      ok: 1,
    });
  }

  @Post('signin')
  async signinByJwt(
    @Res() res: Response,
    @Body() body: SignInAuthDto,
    @Req() req: Request,
  ) {
    const findedUser = await this.userRepo.findOneBy({ Email: body.Email });

    if (!findedUser)
      throw new UnauthorizedException('Email or Password not valid');

    const fingerprint = body.Password;
    const userPassword = findedUser.Password;

    const comparedPassword = await bcrypt.compare(fingerprint, userPassword);

    if (!comparedPassword)
      throw new UnauthorizedException('Email or Password not valid');

    const [AccessToken, RefreshToken] =
      await this.authService.generateTokens(findedUser);

    const { headers } = req;

    const userAgent = headers['user-agent'];

    await this.jwtAuthRepo.delete({ UserAgent: userAgent });

    await this.jwtAuthRepo.save({
      Sub: findedUser.Id,
      Access: AccessToken,
      Refresh: RefreshToken,
      UserAgent: userAgent,
    });

    this.setAuthCookies(res, RefreshToken, AccessToken);
    delete findedUser['Password'];
    res.json({ ok: 1 });
  }

  @HttpCode(201)
  @UseGuards(RefreshTokenGuard)
  @Get('refresh')
  async refreshTokens(@Res() res: Response, @Req() req: Request) {
    if (!req.headers.authorization) throw new UnauthorizedException();
    const refreshToken = req.headers.authorization.split(' ')[1];
    const verifyToken = this.jwtService.verify(refreshToken, {
      secret: this.configService.get('JWT_REFRESH_SECRET'),
    });
    const findedToken = await this.jwtAuthRepo.findOneBy({
      Refresh: refreshToken,
    });

    if (!findedToken) throw new UnauthorizedException();

    await this.jwtAuthRepo.delete({ Refresh: refreshToken });
    const user = await this.userRepo.findOneBy({ Id: verifyToken.Id });

    const [AccessToken, RefreshToken] =
      await this.authService.generateTokens(user);

    const { headers } = req;

    const userAgent = headers['user-agent'];

    await this.jwtAuthRepo.save({
      Sub: user.Id,
      Access: AccessToken,
      Refresh: RefreshToken,
      UserAgent: userAgent,
    });

    this.setAuthCookies(res, RefreshToken, AccessToken);
    res.json({
      ok: 1,
    });
  }

  private setAuthCookies(
    res: Response,
    RefreshToken: string,
    AccessToken: string,
  ) {
    res.cookie('RefreshToken', RefreshToken, {
      httpOnly: true,
      secure: true,
    });
    res.cookie('AccessToken', AccessToken, {
      httpOnly: true,
      secure: true,
    });
  }
}
