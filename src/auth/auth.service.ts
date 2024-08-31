import { BadGatewayException, Injectable } from '@nestjs/common';
import { SignUpAuthDto } from './dto/signup-auth.dto';
import { User } from '../../src/user/entities/user.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { EmailValidation } from './entities/email-validation.entity';
import { SignupDtoWithEmailValidation } from 'types/combined.types';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User) private userRepo: Repository<User>,
    @InjectRepository(EmailValidation)
    private emailValidationRepo: Repository<EmailValidation>,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  findCallbackUUID(uuid: string) {
    return this.emailValidationRepo.findOneBy({ CallBackUUID: uuid });
  }

  private createUserJWT(signUpAuthDto: SignUpAuthDto) {
    return this.userRepo.save({ ...signUpAuthDto, Provider: 'JWT' });
  }
  createUserOAUTH(signUpAuthDto: SignUpAuthDto) {
    return this.userRepo.save({ ...signUpAuthDto, Provider: 'GOOGLE' });
  }

  private deleteEmailUserValidation(uuid: string) {
    return this.emailValidationRepo.delete({ CallBackUUID: uuid });
  }

  /**
   *
   * @param uuid - uuid in db for validation user (delete uuid and create user)
   * @returns {User}
   */
  async signupUserJwt(uuid: string) {
    const user = await this.findCallbackUUID(uuid);
    if (!user) throw new BadGatewayException();
    await this.deleteEmailUserValidation(uuid);
    return await this.createUserJWT(user);
  }

  createEmailUserValidationJWT(signUpAuthDto: SignupDtoWithEmailValidation) {
    return this.emailValidationRepo.save({
      ...signUpAuthDto,
      Provider: 'JWT',
    });
  }

  /**
   *
   * @param user User model in db
   * @returns [AccessToken,RefreshToken]
   */
  async generateTokens(user: User): Promise<string[]> {
    return await Promise.all([
      this.jwtService.signAsync(
        {
          Email: user.Email,
          Id: user.Id,
        },
        {
          secret: this.configService.get('JWT_ACCESS_SECRET'),
          expiresIn: this.configService.get('JWT_ACCESS_TIME'),
        },
      ),
      this.jwtService.signAsync(
        {
          Email: user.Email,
          Id: user.Id,
        },
        {
          secret: this.configService.get('JWT_REFRESH_SECRET'),
          expiresIn: this.configService.get('JWT_REFRESH_TIME'),
        },
      ),
    ]);
  }
}
