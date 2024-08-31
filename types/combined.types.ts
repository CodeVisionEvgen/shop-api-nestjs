import { SignUpAuthDto } from 'src/auth/dto/signup-auth.dto';

export type SignupDtoWithEmailValidation = SignUpAuthDto & {
  CallBackUUID: string;
};
