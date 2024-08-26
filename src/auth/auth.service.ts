import { Injectable } from '@nestjs/common';
import { SignUpAuthDto } from './dto/signup-auth.dto';
import { User } from 'src/user/entities/user.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User) private userRepo: Repository<User>,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}
  async createUserJWT(signUpAuthDto: SignUpAuthDto) {
    return await this.userRepo.save({ ...signUpAuthDto, Provider: 'JWT' });
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
